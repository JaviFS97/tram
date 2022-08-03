## The version used depends on the version used by the server.
## In this case, mitre uses version 20 on its server, so version 20 is used here.
from taxii2client.v20 import ApiRoot, Collection, Server

# from taxii2client.v21 import Collection, Server, ApiRoot

## TAXII Documentation
# https://taxii2client.readthedocs.io/en/latest/index.html#
## TAXII github repository
# https://github.com/oasis-open/cti-taxii-client

## pip install taxii2-client

## Is a TAXII 2.0 Server
server_url = "https://cti-taxii.mitre.org/taxii/"
server_url_default = "https://cti-taxii.mitre.org/taxii/"


def get_server(server_url=server_url_default):
    """
    Returns Server object with the connection.
    Server class contains the following attributes and methods:
        - api_roots        - contact           - custom_properties
        - default          - description       - refresh()

    :param server_url: url of the server you want to connect to (default: 'https://cti-taxii.mitre.org/taxii/')
    """
    try:
        return Server(server_url)
    except:
        pass


def get_server_info(server: Server):
    """
    Obtains basic information from the server.
    {"contact","description","title"}

    :param server: server from which you want to obtain the information
    """
    try:
        return {
            "contact": server.contact,
            "description": server.description,
            "title": server.title,
        }
    except:
        pass


def get_ApiRoot(server: Server, indexApiRoot=0):
    """
    Get one of the ApiRoots defined in a server.
    Each ApiRoot instance gets its own connection pool(s).

    ApiRoot class contains the following attributes and methods:
        - collections       - custom_properties         - description
        - get_status(...)   - max_content_length        - refresh(...)
        - title             - versions

    :param server: ApiRoot is obtained from a Server.
    :param indexApiRoot: position of the apiroot we want from the whole list. Default is the first position.
    """
    return server.api_roots[indexApiRoot]


def get_collectionID(apiroot: ApiRoot, collectionName="Enterprise ATT&CK"):
    """
    Get the ID of the collection of which we want its ID.

    :param apiroot: ApiRoot to which we are connected.
    :param collectionName: name of the collection of which we want its id. Options: {Enterprise ATT&CK, PRE-ATT&CK, Mobile ATT&CK, ICS ATT&CK}
    """

    for collection in apiroot.collections:
        if collection.title == collectionName:
            return collection.id


def get_collection(collectionID):
    """
    Get an instance of a collection. To get it, first you have to pass the collection identifier.
    The format of the collection is STIX+json --> collection.media_types = ['application/vnd.oasis.stix+json; version=2.0']

    Collection class contains the following attributes and methods:
        - custom_properties         - description       - get_manifest(...)
        - get_object(obj_id, ...)   - get_objects(...)  - id
        - manifest_url              - media_types       - objects_url
        - refresh(...)              - title

    :param collectionID: collection identifier.
    """
    return Collection(f"https://cti-taxii.mitre.org/stix/collections/{collectionID}/")


def get_objects_of_collection(collection: Collection):
    """
    You get all the objects from the collection.

    :param collection: collection from which objects are obtained
    """
    return collection.get_objects()


def get_object_of_collection(collection: Collection, objectID):
    """
    You get an object, based on its identifier, from the collection.

    :param collection: collection from which objects are obtained
    :param objectID: identifier of the object to be retrieved. An example: 'indicator--252c7c11-daf2-42bd-843b-be65edca9f61'
    """
    return collection.get_object(objectID)


## An example
# server = get_server()
# get_server_info(server)
# apiroot = get_ApiRoot(server)
# collectionID = get_collectionID(apiroot)
# for collection in apiroot.collections:
#     print(collection.title.ljust(20) + collection.id)
# collection = get_collection(collectionID)
# print(collection.title)
# print(collection.objects_url)
# print(collection.get_objects())
