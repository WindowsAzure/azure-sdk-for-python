# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class JobHistoryDefinition(Model):
    """JobHistoryDefinition

    :param id: Gets the job history identifier.
    :type id: str
    :param type: Gets the job history resource type.
    :type type: str
    :param name: Gets the job history name.
    :type name: str
    :param properties: Gets or sets the job history properties.
    :type properties: :class:`JobHistoryDefinitionProperties
     <schedulermanagementclient.models.JobHistoryDefinitionProperties>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'JobHistoryDefinitionProperties'},
    }

    def __init__(self, id=None, type=None, name=None, properties=None):
        self.id = id
        self.type = type
        self.name = name
        self.properties = properties
