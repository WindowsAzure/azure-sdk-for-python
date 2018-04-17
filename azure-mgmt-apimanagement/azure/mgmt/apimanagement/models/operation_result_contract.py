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

from msrest.serialization import Model


class OperationResultContract(Model):
    """Operation Result.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Operation result identifier.
    :type id: str
    :param status: Status of an async operation. Possible values include:
     'Started', 'InProgress', 'Succeeded', 'Failed'
    :type status: str or ~azure.mgmt.apimanagement.models.AsyncOperationStatus
    :param started: Start time of an async operation. The date conforms to the
     following format: `yyyy-MM-ddTHH:mm:ssZ` as specified by the ISO 8601
     standard.
    :type started: datetime
    :param updated: Last update time of an async operation. The date conforms
     to the following format: `yyyy-MM-ddTHH:mm:ssZ` as specified by the ISO
     8601 standard.
    :type updated: datetime
    :param result_info: Optional result info.
    :type result_info: str
    :param error: Error Body Contract
    :type error: ~azure.mgmt.apimanagement.models.ErrorResponse
    :ivar action_log: This property if only provided as part of the
     TenantConfiguration_Validate operation. It contains the log the entities
     which will be updated/created/deleted as part of the
     TenantConfiguration_Deploy operation.
    :vartype action_log:
     list[~azure.mgmt.apimanagement.models.OperationResultLogItemContract]
    """

    _validation = {
        'action_log': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'status': {'key': 'status', 'type': 'AsyncOperationStatus'},
        'started': {'key': 'started', 'type': 'iso-8601'},
        'updated': {'key': 'updated', 'type': 'iso-8601'},
        'result_info': {'key': 'resultInfo', 'type': 'str'},
        'error': {'key': 'error', 'type': 'ErrorResponse'},
        'action_log': {'key': 'actionLog', 'type': '[OperationResultLogItemContract]'},
    }

    def __init__(self, **kwargs):
        super(OperationResultContract, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.status = kwargs.get('status', None)
        self.started = kwargs.get('started', None)
        self.updated = kwargs.get('updated', None)
        self.result_info = kwargs.get('result_info', None)
        self.error = kwargs.get('error', None)
        self.action_log = None
