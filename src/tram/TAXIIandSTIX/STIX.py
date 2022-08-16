import datetime
import json

from stix2 import Filter, TAXIICollectionSource

## STIX API
# https://stix2.readthedocs.io/en/latest/index.html
## OASIS Standard for STIX
# https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
##
# pip install stix2


TTPs_of_intrusion_sets_file_name = "./src/tram/TAXIIandSTIX/TTPs_of_intrusion_sets.json"
UPDATE_TTPs_of_intrusion_sets_file = False


def collection_to_STIX(collection):
    """
    Receives a collection generated from TAXII and transforms it to STIX format.

    :param collection: collection to transform to STIX format.
    """
    taxii_src = TAXIICollectionSource(collection)

    return taxii_src


def get_intrusion_set(taxii_src: TAXIICollectionSource, intrusion_set_id):
    """
    It returns a group based on its identifier.

    :param taxii_src: collection to transform to STIX format.
    :param intrusion_set_id: of the group you want information about.
    """
    return taxii_src.query(Filter("id", "=", intrusion_set_id))


def get_intrusion_sets(taxii_src: TAXIICollectionSource):
    """
    It returns all the groups in the collection converted to STIX format.
    Intrusion_set in STIX refers to groups.

    :param taxii_src: collection to transform to STIX format.
    """
    return taxii_src.query(Filter("type", "=", "intrusion-set"))


def get_relationship_of_intrusion_set(
    taxii_src: TAXIICollectionSource, intrusion_set_id
):
    """
    The Relationship object is used to link together two SDOs in order to describe how they are related to each other.
    In this case we are looking for all the relations in which an intrusion_set participates, as a source_ref.

    :param taxii_src: collection to transform to STIX format.
    :param intrusion_set_id: identifier of the intrusion_set we want to get the relationship from.
    """
    return taxii_src.query(Filter("source_ref", "=", intrusion_set_id))


def get_TTPs_of_intrusion_sets(taxii_src: TAXIICollectionSource):
    """
    We will not only get the TTPs, but also software used by the intrusion_set.

    [WARNING]!!!!: this process takes several minutes. There is no point in running it every time the application is opened. Save it to disk (along with the creation date) and update it from time to time.

    :param taxii_src: collection to transform to STIX format.
    """
    intrusion_sets = get_intrusion_sets(taxii_src)
    intrusion_sets_with_TTPs = []
    for intrusion_set in intrusion_sets:
        relationship_of_intrusion_set = get_relationship_of_intrusion_set(
            taxii_src, intrusion_set.id
        )

        TTPs = []
        for relationship in relationship_of_intrusion_set:
            attack_pattern = taxii_src.query(
                Filter("id", "=", relationship.target_ref)
            )[0]
            for external_reference in attack_pattern.external_references:
                if external_reference.source_name == "mitre-attack":
                    TTPs.append(external_reference.external_id)

        intrusion_sets_with_TTPs.append(
            {
                "intrusion_set_id": intrusion_set.id,
                "instrusion_set_name": intrusion_set.name,
                "TTPs": TTPs,
            }
        )

    save_TTPs_of_intrusion_sets(intrusion_sets_with_TTPs)


def save_TTPs_of_intrusion_sets(intrusion_sets_with_TTPs):
    with open(TTPs_of_intrusion_sets_file_name, "w") as json_file:
        json.dump(
            {
                "created": str(datetime.datetime.now()),
                "intrusion_sets": intrusion_sets_with_TTPs,
            },
            json_file,
        )


def read_TTPs_of_intrusion_sets():
    with open(TTPs_of_intrusion_sets_file_name) as json_file:
        return json.load(json_file)


def update_TTPs_of_intrusion_sets_file(collection):
    """
    Downloading the ttps of each group to the "./src/tram/TAXIIandSTIX/TTPs_of_intrusion_sets.json" file.
    It is a rather slow process, it can take half an hour.

    Execute only when UPDATE_TTPs_of_intrusion_sets_file variable is TRUE

    :param collection: collection to transform to STIX format.
    """
    get_TTPs_of_intrusion_sets(collection_to_STIX(collection))


def get_attack_patterns(taxii_src: TAXIICollectionSource):
    """
    It returns all TTPs.

    :param taxii_src: collection to transform to STIX format.
    """
    return taxii_src.query(Filter("type", "=", "attack-pattern"))


def get_relationships_of_attack_pattern(
    taxii_src: TAXIICollectionSource, attack_pattern_id
):
    """
    The Relationship object is used to link together two SDOs in order to describe how they are related to each other.
    In this case we are looking for all the relations in which an attack_pattern_id participates, as a target_ref.

    :param taxii_src: collection to transform to STIX format.
    :param attack_pattern_id: identifier of the attack_pattern_id we want to get the relationship from.
    """
    return taxii_src.query(Filter("target_ref", "=", attack_pattern_id))


def get_mitigations(taxii_src: TAXIICollectionSource):
    """
    It returns all Mitigations. Mitigations are only found within the object "relationship".

    :param taxii_src: collection to transform to STIX format.
    """
    return taxii_src.query(Filter("relationship_type", "=", "mitigates"))


def get_mitigations_and_detections_of_attack_pattern(
    taxii_src: TAXIICollectionSource, report_TTPs
):
    """
    Obtains the mitigations and detection of the TTPs present in the report.

    [WARNING]!!!!: this process takes ~15sec.
    [TODO] [As an improvement] There is no point in running it every time the application is opened. Save it to disk (along with the creation date) and update it from time to time.

    :param taxii_src: collection to transform to STIX format.
    :param report_TTPs: all TTPs involved in this report.
    """
    mitigations = get_mitigations(taxii_src)
    attack_patterns = get_attack_patterns(taxii_src)
    attack_pattern_with_mitigations_and_detections = []
    for attack_pattern in attack_patterns:
        if attack_pattern.external_references[0].external_id in report_TTPs:

            # Gets attack_pattern mitigations
            attack_pattern_mitigations = []
            for mitigation in mitigations:
                if mitigation.target_ref == attack_pattern.id:
                    attack_pattern_mitigations.append(mitigation)

            # Gets attack_pattern detections
            attack_pattern_detections = attack_pattern.x_mitre_detection

            attack_pattern_with_mitigations_and_detections.append(
                {
                    "attack_pattern": attack_pattern,
                    "attack_pattern_id": attack_pattern.external_references[
                        0
                    ].external_id,
                    "attack_pattern_mitigations": attack_pattern_mitigations,
                    "attack_pattern_detections": attack_pattern_detections,
                }
            )

    return attack_pattern_with_mitigations_and_detections
