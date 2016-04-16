# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class RoleAssignmentCreateParameters(Model):
    """
    Role assignment create parameters.

    :param properties: Gets or sets role assignment properties.
    :type properties: :class:`RoleAssignmentProperties
     <authorizationmanagementclient.models.RoleAssignmentProperties>`
    """ 

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'RoleAssignmentProperties'},
    }

    def __init__(self, properties=None):
        self.properties = properties
