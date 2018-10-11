# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .validate_operation_request_py3 import ValidateOperationRequest


class ValidateRestoreOperationRequest(ValidateOperationRequest):
    """AzureRestoreValidation request.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: ValidateIaasVMRestoreOperationRequest

    All required parameters must be populated in order to send to Azure.

    :param object_type: Required. Constant filled by server.
    :type object_type: str
    :param restore_request: Sets restore request to be validated
    :type restore_request:
     ~azure.mgmt.recoveryservicesbackup.models.RestoreRequest
    """

    _validation = {
        'object_type': {'required': True},
    }

    _attribute_map = {
        'object_type': {'key': 'objectType', 'type': 'str'},
        'restore_request': {'key': 'restoreRequest', 'type': 'RestoreRequest'},
    }

    _subtype_map = {
        'object_type': {'ValidateIaasVMRestoreOperationRequest': 'ValidateIaasVMRestoreOperationRequest'}
    }

    def __init__(self, *, restore_request=None, **kwargs) -> None:
        super(ValidateRestoreOperationRequest, self).__init__(**kwargs)
        self.restore_request = restore_request
        self.object_type = 'ValidateRestoreOperationRequest'
