import datetime
import json

from stix2 import Filter, TAXIICollectionSource

## Aqui está la API de STIX
# https://stix2.readthedocs.io/en/latest/index.html
##
# pip install stix2


TTPs_of_intrusion_sets_file_name = "./src/tram/TAXIIandSTIX/TTPs_of_intrusion_sets.json"


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
    i = 0
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

        print("VALOR --> " + str(i))
        print("Nombre: " + intrusion_set.name + "TTPs" + TTPs)
        print("\n\n\n\n\n")
        intrusion_sets_with_TTPs.append(
            {
                "intrusion_set_id": intrusion_set.id,
                "instrusion_set_name": intrusion_set.name,
                "TTPs": TTPs,
            }
        )

    save_TTPs_of_intrusion_sets(intrusion_sets_with_TTPs)
    # return intrusion_sets_with_TTPs


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
        data = json.load(json_file)
        return data
        # print(data["intrusion_sets"])
        print(len(data["intrusion_sets"]))
        for i in data["intrusion_sets"]:
            print(i)
