# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource_management_error import ResourceManagementError


class ResourceManagementErrorWithDetails(ResourceManagementError):
    """ResourceManagementErrorWithDetails

    :param code: Gets or sets the error code returned from the server.
    :type code: str
    :param message: Gets or sets the error message returned from the server.
    :type message: str
    :param target: Gets or sets the target of the error.
    :type target: str
    :param details: Gets or sets validation error.
    :type details: list of :class:`ResourceManagementError
     <resourcemanagementclient.models.ResourceManagementError>`
    """ 

    _validation = {
        'code': {'required': True},
        'message': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ResourceManagementError]'},
    }

    def __init__(self, code, message, target=None, details=None):
        super(ResourceManagementErrorWithDetails, self).__init__(code=code, message=message, target=target)
        self.details = details
