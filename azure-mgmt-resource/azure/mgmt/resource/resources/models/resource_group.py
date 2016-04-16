# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ResourceGroup(Model):
    """
    Resource group information.

    :param id: Gets the ID of the resource group.
    :type id: str
    :param name: Gets or sets the Name of the resource group.
    :type name: str
    :param properties:
    :type properties: :class:`ResourceGroupProperties
     <resourcemanagementclient.models.ResourceGroupProperties>`
    :param location: Gets or sets the location of the resource group. It
     cannot be changed after the resource group has been created. Has to be
     one of the supported Azure Locations, such as West US, East US, West
     Europe, East Asia, etc.
    :type location: str
    :param tags: Gets or sets the tags attached to the resource group.
    :type tags: dict
    """ 

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'ResourceGroupProperties'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, location, id=None, name=None, properties=None, tags=None):
        self.id = id
        self.name = name
        self.properties = properties
        self.location = location
        self.tags = tags
