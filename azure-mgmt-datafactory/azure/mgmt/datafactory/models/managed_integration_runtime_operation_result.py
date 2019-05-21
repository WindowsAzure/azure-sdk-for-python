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


class ManagedIntegrationRuntimeOperationResult(Model):
    """Properties of managed integration runtime operation result.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :ivar type: The operation type. Could be start or stop.
    :vartype type: str
    :ivar start_time: The start time of the operation.
    :vartype start_time: datetime
    :ivar result: The operation result.
    :vartype result: str
    :ivar error_code: The error code.
    :vartype error_code: str
    :ivar parameters: Managed integration runtime error parameters.
    :vartype parameters: list[str]
    :ivar activity_id: The activity id for the operation request.
    :vartype activity_id: str
    """

    _validation = {
        'type': {'readonly': True},
        'start_time': {'readonly': True},
        'result': {'readonly': True},
        'error_code': {'readonly': True},
        'parameters': {'readonly': True},
        'activity_id': {'readonly': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'type': {'key': 'type', 'type': 'str'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'result': {'key': 'result', 'type': 'str'},
        'error_code': {'key': 'errorCode', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '[str]'},
        'activity_id': {'key': 'activityId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ManagedIntegrationRuntimeOperationResult, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.type = None
        self.start_time = None
        self.result = None
        self.error_code = None
        self.parameters = None
        self.activity_id = None
