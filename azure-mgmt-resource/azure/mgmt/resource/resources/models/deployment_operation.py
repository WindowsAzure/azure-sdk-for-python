# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class DeploymentOperation(Model):
    """
    Deployment operation information.

    :param id: Gets or sets full deployment operation id.
    :type id: str
    :param operation_id: Gets or sets deployment operation id.
    :type operation_id: str
    :param properties: Gets or sets deployment properties.
    :type properties: :class:`DeploymentOperationProperties
     <resourcemanagementclient.models.DeploymentOperationProperties>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'operation_id': {'key': 'operationId', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'DeploymentOperationProperties'},
    }

    def __init__(self, id=None, operation_id=None, properties=None):
        self.id = id
        self.operation_id = operation_id
        self.properties = properties
