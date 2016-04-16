# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class NotificationHubCreateOrUpdateParameters(Model):
    """
    Parameters supplied to the CreateOrUpdate NotificationHub operation.

    :param location: Gets or sets NotificationHub data center location.
    :type location: str
    :param tags: Gets or sets NotificationHub tags.
    :type tags: dict
    :param properties: Gets or sets properties of the NotificationHub.
    :type properties: :class:`NotificationHubProperties
     <notificationhubsmanagementclient.models.NotificationHubProperties>`
    """ 

    _validation = {
        'location': {'required': True},
        'properties': {'required': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'NotificationHubProperties'},
    }

    def __init__(self, location, properties, tags=None):
        self.location = location
        self.tags = tags
        self.properties = properties
