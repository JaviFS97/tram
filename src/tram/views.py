import json
import logging
import time
from urllib.parse import quote

from constance import config
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST
from rest_framework import renderers, viewsets
from rest_framework.decorators import api_view
from rest_framework.response import Response

from tram import serializers
from tram.ml import base
from tram.models import (
    AttackObject,
    Document,
    DocumentProcessingJob,
    Mapping,
    Report,
    Sentence,
)
from tram.renderers import DocxReportRenderer
from tram.TAXIIandSTIX import STIX, TAXII_client

logger = logging.getLogger(__name__)


class AttackObjectViewSet(viewsets.ModelViewSet):
    queryset = AttackObject.objects.all()
    serializer_class = serializers.AttackObjectSerializer


class DocumentProcessingJobViewSet(viewsets.ModelViewSet):
    queryset = DocumentProcessingJob.objects.all()
    serializer_class = serializers.DocumentProcessingJobSerializer


class MappingViewSet(viewsets.ModelViewSet):
    queryset = Mapping.objects.all()
    serializer_class = serializers.MappingSerializer

    def get_queryset(self):
        queryset = MappingViewSet.queryset
        sentence_id = self.request.query_params.get("sentence-id", None)
        if sentence_id:
            queryset = queryset.filter(sentence__id=sentence_id)

        return queryset


class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all()
    serializer_class = serializers.ReportSerializer


class ReportMappingViewSet(viewsets.ModelViewSet):
    """
    This viewset provides access to report mappings.
    """

    serializer_class = serializers.ReportExportSerializer
    renderer_classes = [renderers.JSONRenderer, DocxReportRenderer]

    def get_queryset(self):
        """
        Override parent implementation to support lookup by document ID.
        """
        queryset = Report.objects.all()
        document_id = self.request.query_params.get("doc-id", None)
        if document_id:
            queryset = queryset.filter(document__id=document_id)

        return queryset

    def retrieve(self, request, pk=None):
        """
        Get the mappings for a report.

        Overrides the parent implementation to add a Content-Disposition header
        so that the browser will download instead of displaying inline.

        :param request: HTTP request
        :param pk: primary key of a report
        """
        response = super().retrieve(request, request, pk)
        report = self.get_object()
        filename = "{}.{}".format(
            quote(report.name, safe=""), request.accepted_renderer.format
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class ReportATTCKNavigatorViewSet(viewsets.ModelViewSet):
    """
    This viewset provides access to ATTCK mappings.
    """

    def get_queryset(self):
        """
        Override parent implementation to support lookup by document ID.
        """
        queryset = Report.objects.all()
        document_id = self.request.query_params.get("doc-id", None)
        if document_id:
            queryset = queryset.filter(document__id=document_id)

        return queryset

    def retrieve(self, request, pk=None):
        """
        Get the mappings for a report in a format suitable for importing into the attck matrix.

        Overrides the parent implementation to add a Content-Disposition header
        so that the browser will download instead of displaying inline.

        :param request: HTTP request
        :param pk: primary key of a report
        """
        report = self.get_object()
        mappings = Mapping.objects.filter(report=report.id)
        filename = "{}.{}".format(
            quote(report.name, safe=""), request.accepted_renderer.format
        )

        response_format = {
            "name": report.name,
            "version": "4.3",
            "description": "All techniques used by " + report.name,
            "domain": "mitre-enterprise",
        }

        mappingList = []
        for m in mappings:
            x = {
                "techniqueID": m.attack_object.attack_id,
                "comment": "Confidence: " + str("{:.2f}".format(m.confidence)),
                "color": "#6610f2",
            }
            mappingList.append(x)

        response_format["techniques"] = mappingList
        response = Response(response_format)
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class SentenceViewSet(viewsets.ModelViewSet):
    queryset = Sentence.objects.all()
    serializer_class = serializers.SentenceSerializer

    def get_queryset(self):
        queryset = SentenceViewSet.queryset
        report_id = self.request.query_params.get("report-id", None)
        if report_id:
            queryset = queryset.filter(report__id=report_id)

        attack_id = self.request.query_params.get("attack-id", None)
        if attack_id:
            sentences = Mapping.objects.filter(
                attack_object__attack_id=attack_id
            ).values("sentence")
            queryset = queryset.filter(id__in=sentences)
        return queryset


@login_required
def index(request):
    jobs = DocumentProcessingJob.objects.all()
    job_serializer = serializers.DocumentProcessingJobSerializer(jobs, many=True)

    reports = Report.objects.all()
    report_serializer = serializers.ReportSerializer(reports, many=True)

    context = {
        "job_queue": job_serializer.data,
        "reports": report_serializer.data,
    }

    return render(request, "index.html", context=context)


@login_required
@require_POST
def upload(request):
    """Places a file into ml-pipeline for analysis"""
    # Initialize the processing job.
    dpj = None

    # Initialize response.
    response = {"message": "File saved for processing."}

    file_content_type = request.FILES["file"].content_type
    if file_content_type in (
        "application/pdf",  # .pdf files
        "text/html",  # .html files
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",  # .docx files
        "text/plain",  # .txt files
    ):
        dpj = DocumentProcessingJob.create_from_file(
            request.FILES["file"], request.user
        )
    elif file_content_type in ("application/json",):  # .json files
        json_data = json.loads(request.FILES["file"].read())
        res = serializers.ReportExportSerializer(data=json_data)

        if res.is_valid():
            res.save(created_by=request.user)
        else:
            return HttpResponseBadRequest(res.errors)
    else:
        return HttpResponseBadRequest("Unsupported file type")

    if dpj:
        response["job-id"] = dpj.pk
        response["doc-id"] = dpj.document.pk

    return JsonResponse(response)


@login_required
def ml_home(request):
    techniques = AttackObject.get_sentence_counts()
    model_metadata = base.ModelManager.get_all_model_metadata()

    context = {
        "techniques": techniques,
        "ML_ACCEPT_THRESHOLD": config.ML_ACCEPT_THRESHOLD,
        "ML_CONFIDENCE_THRESHOLD": config.ML_CONFIDENCE_THRESHOLD,
        "models": model_metadata,
    }

    return render(request, "ml_home.html", context)


@login_required
def ml_technique_sentences(request, attack_id):
    techniques = AttackObject.objects.all().order_by("attack_id")
    techniques_serializer = serializers.AttackObjectSerializer(techniques, many=True)

    context = {"attack_id": attack_id, "attack_techniques": techniques_serializer.data}
    return render(request, "technique_sentences.html", context)


@login_required
def ml_model_detail(request, model_key):
    try:
        model_metadata = base.ModelManager.get_model_metadata(model_key)
    except ValueError:
        raise Http404("Model does not exists")
    context = {"model": model_metadata}
    return render(request, "model_detail.html", context)


@login_required
def analyze(request, pk):
    report = Report.objects.get(id=pk)
    techniques = AttackObject.objects.all().order_by("attack_id")
    techniques_serializer = serializers.AttackObjectSerializer(techniques, many=True)

    context = {
        "report_id": report.id,
        "report_name": report.name,
        "attack_techniques": techniques_serializer.data,
    }
    return render(request, "analyze.html", context)


@login_required
def summary(request, pk):
    report = Report.objects.get(id=pk)

    # Get TAXII connection and STIX representation
    TAXIIserver = TAXII_client.get_server()
    STIXrepresentation = STIX.collection_to_STIX(
        TAXII_client.get_collection(
            TAXII_client.get_collectionID(TAXII_client.get_ApiRoot(TAXIIserver))
        )
    )

    # Get report TTPs
    mappings = Mapping.objects.filter(report=report.id)
    report_TTPs = []
    for m in mappings:
        report_TTPs.append(m.attack_object.attack_id)

    def get_top3_groups_matched_by_TTPs():
        results = []
        intrusion_sets_TTPs = STIX.read_TTPs_of_intrusion_sets()
        for intrusion_set in intrusion_sets_TTPs["intrusion_sets"]:
            TTPs = []
            for ttp in intrusion_set["TTPs"]:
                if ttp in report_TTPs:
                    TTPs.append(ttp)

            results.append(
                {
                    "instrusion_set_name": intrusion_set["instrusion_set_name"],
                    "intrusion_set_id": intrusion_set["intrusion_set_id"],
                    "matchTTPs|totalTTPs": str(len(TTPs))
                    + "|"
                    + str(len(intrusion_set["TTPs"])),
                    "matchTTPs/totalTTPs": str(
                        len(TTPs) / len(intrusion_set["TTPs"])
                        if len(intrusion_set["TTPs"])
                        else 0
                    )
                    + "%",
                    "TTPs_matched": TTPs,
                    "TTPs_intrusion_set": intrusion_set["TTPs"],
                }
            )

        ## [TODO] ordenar los resultados
        return results[0], results[1], results[2]

    top1, top2, top3 = get_top3_groups_matched_by_TTPs()

    ### [TODO] HACER EN OTRA PARTE LA DESCARGA DE LOS GRUPOS
    # server = TAXII_client.get_server()
    # ## TAXII_client.get_server_info(server)
    # apiroot = TAXII_client.get_ApiRoot(server)
    # collectionID = TAXII_client.get_collectionID(apiroot)
    # collection = TAXII_client.get_collection(collectionID)
    # print(STIX.get_TTPs_of_intrusion_sets(STIX.collection_to_STIX(collection)))

    # ttps = [{"intrusion_set_id": "intrusion-set--64b52e7d-b2c4-4a02-9372-08a463f5dc11", "instrusion_set_name": "Aquatic Panda", "TTPs": ["T1588.002", "T1588.001", "T1574.001", "T1027", "T1082", "T1007", "T1059.003", "S0385", "S0154", "T1560.001", "T1070.004", "T1003.001", "T1105", "T1059.001", "T1562.001", "T1595.002", "T1518.001"]}, {"intrusion_set_id": "intrusion-set--6eded342-33e5-4451-b6b2-e1c62863129f", "instrusion_set_name": "Confucius", "TTPs": ["T1218.005", "T1059.005", "T1567.002", "T1583.006", "S0670", "T1566.001", "T1566.002", "T1204.001", "T1204.002", "T1059.001", "T1071.001", "T1203", "T1221", "T1105", "T1119", "T1053.005", "T1041", "T1083", "T1547.001", "T1082"]}, {"intrusion_set_id": "intrusion-set--99910207-1741-4da1-9b5d-537410186b51", "instrusion_set_name": "Gelsemium", "TTPs": []}, {"intrusion_set_id": "intrusion-set--abc5a1d4-f0dc-49d1-88a1-4a80e478bb03", "instrusion_set_name": "LazyScripter", "TTPs": ["T1583.006", "T1583.001", "T1608.001", "T1588.001", "T1105", "T1204.001", "T1204.002", "S0669", "T1059.007", "S0363", "T1036", "T1071.004", "T1218.011", "T1218.005", "T1102", "S0508", "S0262", "S0332", "S0250", "T1059.005", "S0385", "T1059.001", "T1547.001", "T1027", "T1059.003", "T1566.002", "T1566.001"]}, {"intrusion_set_id": "intrusion-set--35d1b3be-49d4-42f1-aaa6-ef159c880bca", "instrusion_set_name": "TeamTNT", "TTPs": ["S0683", "T1552.004", "T1105", "T1587.001", "T1611", "T1609", "S0179", "T1133", "T1021.004", "T1496", "S0349", "T1608.001", "T1136.001", "T1046", "S0601", "T1204.003", "T1552.001", "T1219", "T1583.001", "T1610", "T1071.001", "T1070.003", "T1049", "T1613", "T1595.001", "T1552.005", "T1543.002", "T1027", "T1057", "T1595.002", "T1222.002", "T1016", "T1014", "T1027.002", "T1059.004", "T1543.003", "T1071", "T1059.003", "T1059.001", "T1547.001", "T1518.001", "T1082", "T1562.001", "T1070.004", "T1098.004", "T1102", "T1070.002", "T1562.004"]}, {"intrusion_set_id": "intrusion-set--39d6890e-7f23-4474-b8ef-e7b0343c5fc8", "instrusion_set_name": "Andariel", "TTPs": ["T1590.005", "T1189", "T1592.002", "T1049", "T1204.002", "T1057", "S0032", "T1105", "T1027.003", "S0433", "T1005", "T1566.001", "T1203", "T1588.001"]}, {"intrusion_set_id": "intrusion-set--6566aac9-dad8-4332-ae73-20c23bad7f02", "instrusion_set_name": "Ferocious Kitten", "TTPs": ["T1588.002", "S0652", "T1566.001", "T1036.005", "T1036.002", "T1204.002", "T1583.001", "S0190"]}, {"intrusion_set_id": "intrusion-set--e5603ea8-4c36-40e7-b7af-a077d24fedc1", "instrusion_set_name": "IndigoZebra", "TTPs": ["T1586.002", "T1583.001", "T1105", "T1588.002", "S0653", "S0651", "S0012", "T1204.002", "T1566.001", "T1583.006"]}, {"intrusion_set_id": "intrusion-set--9735c036-8ebe-47e9-9c77-b0ae656dab93", "instrusion_set_name": "BackdoorDiplomacy", "TTPs": ["T1120", "T1074.001", "T1505.003", "S0647", "T1588.002", "T1027", "T1095", "T1036.004", "T1190", "T1049", "T1036.005", "T1046", "T1574.001", "T1105", "T1588.001", "T1055.001", "S0020", "S0002", "S0590", "S0262"]}, {"intrusion_set_id": "intrusion-set--e44e0985-bc65-4a8f-b578-211c858128e3", "instrusion_set_name": "Transparent Tribe", "TTPs": ["T1189", "T1566.002", "S0643", "S0334", "S0644", "T1204.001", "T1564.001", "T1036.005", "T1568", "T1059.005", "T1583.001", "T1584.001", "S0385", "T1608.004", "S0115", "T1566.001", "T1204.002", "T1203", "T1027"]}, {"intrusion_set_id": "intrusion-set--fed4f0a2-4347-4530-b0f5-6dfd49b29172", "instrusion_set_name": "Nomadic Octopus", "TTPs": ["T1204.002", "T1564.003", "T1059.001", "T1105", "T1059.003", "S0340", "T1036", "T1566.001"]}, {"intrusion_set_id": "intrusion-set--bb82e0b0-6e9c-439f-970a-4c917a74c5f2", "instrusion_set_name": "CostaRicto", "TTPs": ["T1588.002", "S0615", "T1046", "S0614", "S0613", "S0029", "S0183", "T1572", "S0194", "T1090.003", "T1053.005"]}, {"intrusion_set_id": "intrusion-set--c5b81590-6814-4d2a-8baa-15c4b6c7f960", "instrusion_set_name": "Tonto Team", "TTPs": ["T1090.002", "S0008", "S0590", "T1068", "S0349", "T1135", "T1003", "T1059.006", "T1056.001", "T1210", "T1069.001", "T1505.003", "T1059.001", "T1105", "T1574.001", "S0002", "T1566.001", "T1203", "T1204.002", "S0268", "S0596"]}, {"intrusion_set_id": "intrusion-set--fa19de15-6169-428d-9cd6-3ca3d56075b7", "instrusion_set_name": "Ajax Security Team", "TTPs": ["S0224", "S0225", "T1555.003", "T1056.001", "T1566.003", "T1566.001", "T1105", "T1204.002"]}, {"intrusion_set_id": "intrusion-set--420ac20b-f2b9-42b8-aa1a-6d4b72895ca4", "instrusion_set_name": "Mustang Panda", "TTPs": ["S0662", "T1608.001", "T1102", "T1585.002", "T1608", "T1036.007", "T1560.003", "T1218.004", "T1091", "T1052.001", "T1049", "T1082", "T1566.001", "T1036.005", "T1027.001", "T1057", "T1573.001", "T1016", "T1105", "T1547.001", "T1564.001", "T1083", "T1566.002", "S0590", "T1119", "T1219", "T1003.003", "T1074.001", "T1070.004", "T1583.001", "T1546.003", "T1218.005", "T1560.001", "T1518", "T1053.005", "T1059.003", "T1574.002", "T1047", "T1071.001", "S0013", "T1204.001", "S0012", "S0154", "T1203", "T1027", "T1204.002", "T1059.001", "T1059.005"]}, {"intrusion_set_id": "intrusion-set--4283ae19-69c7-4347-a35e-b56f08eb660b", "instrusion_set_name": "ZIRCONIUM", "TTPs": ["T1016", "T1567.002", "T1036.004", "T1140", "T1068", "T1027.002", "T1105", "T1041", "T1059.003", "T1033", "T1573.001", "T1082", "T1124", "T1012", "T1555.003", "T1547.001", "T1218.007", "T1204.001", "T1036", "T1102.002", "T1598", "T1583.006", "T1059.006", "T1566.002", "T1583.001"]}]
    # STIX.save_TTPs_of_intrusion_sets(ttps)

    context = {
        "report_id": report.id,
        "report_name": report.name,
        # "TAXII_server_info": TAXII_client.get_server_info(TAXIIserver),
        "top1_group": STIX.get_intrusion_set(
            STIXrepresentation, top1["intrusion_set_id"]
        )[0],
        "top2_group": STIX.get_intrusion_set(
            STIXrepresentation, top2["intrusion_set_id"]
        )[0],
        "top3_group": STIX.get_intrusion_set(
            STIXrepresentation, top3["intrusion_set_id"]
        )[0],
    }

    return render(request, "summary.html", context)


@login_required
def download_document(request, doc_id):
    """Download a verbatim copy of a previously uploaded document."""
    doc = Document.objects.get(id=doc_id)
    docfile = doc.docfile

    try:
        with docfile.open("rb") as report_file:
            response = HttpResponse(
                report_file, content_type="application/octet-stream"
            )
            filename = quote(docfile.name)
            response["Content-Disposition"] = f"attachment; filename={filename}"
    except IOError:
        raise Http404("File does not exist")

    return response


@api_view(["POST"])
def train_model(request, name):
    """
    Train the specified model.

    Runs training synchronously and returns a response when the training is
    complete.

    :param name: the name of the model
    """
    try:
        model = base.ModelManager(name)
    except ValueError:
        raise Http404("Model does not exist")

    logger.info(f"Training ML Model: {name}")
    start = time.time()
    model.train_model()
    elapsed = time.time() - start
    logger.info("Trained ML model in %0.3f seconds", elapsed)

    return Response(
        {
            "message": "Model successfully trained.",
            "elapsed_sec": elapsed,
        }
    )
