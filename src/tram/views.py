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


def IOCDetails(request):
    import json

    from tram.AlienVault import otx_client

    IOC_value = request.GET["IOC_value"]
    IOC_type = request.GET["IOC_type"]

    if IOC_type == "IP":
        result = otx_client.get_ip_alerts(IOC_value)
        print(result)
        return HttpResponse(json.dumps(result))

    # response_format = {
    #     "version": "4.3",
    #     "domain": "mitre-enterprise",
    # }
    # response = Response(response_format)

    # return response

    return HttpResponse("holaaaaa")


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

    # The process of downloading the ttps of each group to the "./src/tram/TAXIIandSTIX/TTPs_of_intrusion_sets.json" file usually takes half an hour.
    if STIX.UPDATE_TTPs_of_intrusion_sets_file:
        STIX.update_TTPs_of_intrusion_sets_file(STIXrepresentation)

    # Get report TTPs
    mappings = Mapping.objects.filter(report=report.id)
    report_TTPs_set = set()
    for m in mappings:
        report_TTPs_set.add(m.attack_object.attack_id)

    report_TTPs = list(report_TTPs_set)

    def get_keywords():
        """
        Obtains all the keywords in the text by applying regular expressions on the text.
        The patterns used as regular expressions can be found in the file: settings.DATA_DIRECTORY / "Keywords-patterns.json"
        """
        import json
        import re

        from django.conf import settings
        from nltk.stem import WordNetLemmatizer

        wnl = WordNetLemmatizer()
        report_keywords = {}
        with open(settings.DATA_DIRECTORY / "Keywords-patterns.json", "r") as f:
            patters_json = json.load(f)

            for pattern in patters_json["patterns"]:
                pattern_name, pattern_values, pattern_pos_tag_type = (
                    pattern["name"],
                    pattern["values"],
                    pattern["pos_tag_type"],
                )

                keywords = set(
                    re.findall(pattern_values, report.text)
                )  # Applies regular expressions over the entire text
                keywords_lemmas = set()

                for word in keywords:
                    keyword_lemma = wnl.lemmatize(
                        word, pattern_pos_tag_type
                    )  # Gets the lemma of each word to avoid repetitions in dictionary
                    keywords_lemmas.add(keyword_lemma)

                report_keywords[pattern_name] = keywords

            return report_keywords

    def get_abstract(report_text):
        """
        Get the summary of the report itself.

        It searches, with the regular expressions defined in the variable "regex", the summary in the first 5000 words of the report.
        In case of finding matches in the first 5000 words of the report, a total of 1000 are extracted as part of the executive summary.

        :param report_text: All report content in plain text format.
        """
        import re

        regex = "Executive Summary"  # [TODO] Add more titles related to the summary
        ABSTRACT_SEARCH_LENGTH = 5000
        ABSTRACT_LENGHT = 1000

        try:
            return (
                re.split(regex, report_text[:ABSTRACT_SEARCH_LENGTH])[-1][
                    :ABSTRACT_LENGHT
                ]
                + "..."
            )
        except:
            return "No summary exists or could not be retrieved."

    def get_top3_groups_matched_by_TTPs():
        results = []
        intrusion_sets_TTPs = STIX.read_TTPs_of_intrusion_sets()
        for intrusion_set in intrusion_sets_TTPs["intrusion_sets"]:
            TTPs = []
            for ttp in intrusion_set["TTPs"]:
                if "S" in ttp:
                    pass
                else:
                    if ttp in report_TTPs:
                        TTPs.append(ttp)

            results.append(
                {
                    "instrusion_set_name": intrusion_set["instrusion_set_name"],
                    "intrusion_set_id": intrusion_set["intrusion_set_id"],
                    "matchTTPs|totalTTPs": str(len(TTPs)) + "|" + str(len(report_TTPs)),
                    "matchTTPs/totalTTPs": str(
                        len(TTPs) / len(report_TTPs) if len(report_TTPs) else 0
                    )
                    + "%",
                    "TTPs_matched": TTPs,
                    "TTPs_intrusion_set": intrusion_set["TTPs"],
                }
            )

        top3 = []
        for i in range(3):
            max = maxPosition = index = 0
            for r in results:
                value = float(r["matchTTPs/totalTTPs"].split("%")[0])
                if value > max:
                    max = value
                    maxPosition = index
                index += 1

            top3.append(results.pop(maxPosition))

        return top3[0], top3[1], top3[2]

    def get_TTPs_matched_0or1(report_TTPs, TTPs_intrusion_set):
        TTPs_matched_0or1 = []
        for report_TTP in report_TTPs:
            if report_TTP in TTPs_intrusion_set:
                TTPs_matched_0or1.append(1)
            else:
                TTPs_matched_0or1.append(0)
        return TTPs_matched_0or1

    def get_IOCs():
        """
        Obtains all the IOCs in the text by applying regular expressions on the text.
        The patterns used as regular expressions can be found in the file: settings.DATA_DIRECTORY / "IOCs-patterns.json"
        """
        import json
        import re

        from django.conf import settings
        from nltk.stem import WordNetLemmatizer

        wnl = WordNetLemmatizer()
        report_keywords = {}
        with open(settings.DATA_DIRECTORY / "IOCs-patterns.json", "r") as f:
            patters_json = json.load(f)

            for pattern in patters_json["patterns"]:
                pattern_name, pattern_values = (pattern["name"], pattern["values"])

                keywords = set(
                    re.findall(pattern_values, report.text)
                )  # Applies regular expressions over the entire text

                report_keywords[pattern_name] = keywords

            return report_keywords

    top1, top2, top3 = get_top3_groups_matched_by_TTPs()

    context = {
        "report_info": {
            "name": report.name,
            "id": report.id,
            "created_by": report.created_by,
            "created_on": report.created_on,
            "updated_on": report.updated_on,
        },
        "report_abstract": get_abstract(report.text),
        "report_keywords": get_keywords(),
        "report_IOCs": get_IOCs(),
        "report_TTPs": report_TTPs,
        "TAXII_server_info": TAXII_client.get_server_info(TAXIIserver),
        "top1_group": STIX.get_intrusion_set(
            STIXrepresentation, top1["intrusion_set_id"]
        )[0],
        "top2_group": STIX.get_intrusion_set(
            STIXrepresentation, top2["intrusion_set_id"]
        )[0],
        "top3_group": STIX.get_intrusion_set(
            STIXrepresentation, top3["intrusion_set_id"]
        )[0],
        "top1_grooup_TTPs_matched_0or1": get_TTPs_matched_0or1(
            report_TTPs, top1["TTPs_intrusion_set"]
        ),  # data for bar char
        "top2_grooup_TTPs_matched_0or1": get_TTPs_matched_0or1(
            report_TTPs, top2["TTPs_intrusion_set"]
        ),  # data for bar char
        "top3_grooup_TTPs_matched_0or1": get_TTPs_matched_0or1(
            report_TTPs, top3["TTPs_intrusion_set"]
        ),  # data for bar char,
        # "attack_pattern_mitigations_and_detections": STIX.get_mitigations_and_detections_of_attack_pattern(
        #     STIXrepresentation, report_TTPs
        # ),
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
