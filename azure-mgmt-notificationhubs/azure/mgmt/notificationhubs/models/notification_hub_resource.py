# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class NotificationHubResource(Model):
    """
    Description of a NotificatioHub Resource.

    :param id: Gets or sets the id of the created NotificatioHub.
    :type id: str
    :param location: Gets or sets datacenter location of the NotificatioHub.
    :type location: str
    :param name: Gets or sets name of the NotificatioHub.
    :type name: str
    :param type: Gets or sets resource type of the NotificatioHub.
    :type type: str
    :param tags: Gets or sets tags of the NotificatioHub.
    :type tags: dict
    :param properties: Gets or sets properties of the NotificatioHub.
    :type properties: :class:`NotificationHubProperties
     <notificationhubsmanagementclient.models.NotificationHubProperties>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'NotificationHubProperties'},
    }

    def __init__(self, id=None, location=None, name=None, type=None, tags=None, properties=None):
        self.id = id
        self.location = location
        self.name = name
        self.type = type
        self.tags = tags
        self.properties = properties
