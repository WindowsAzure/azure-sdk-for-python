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


class RetryHistory(Model):
    """The retry history.

    :param start_time: Gets the start time.
    :type start_time: datetime
    :param end_time: Gets the end time.
    :type end_time: datetime
    :param code: Gets the status code.
    :type code: str
    :param client_request_id: Gets the client request Id.
    :type client_request_id: str
    :param service_request_id: Gets the service request Id.
    :type service_request_id: str
    :param error: Gets the error response.
    :type error: ~azure.mgmt.logic.models.ErrorResponse
    """

    _attribute_map = {
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'code': {'key': 'code', 'type': 'str'},
        'client_request_id': {'key': 'clientRequestId', 'type': 'str'},
        'service_request_id': {'key': 'serviceRequestId', 'type': 'str'},
        'error': {'key': 'error', 'type': 'ErrorResponse'},
    }

    def __init__(self, start_time=None, end_time=None, code=None, client_request_id=None, service_request_id=None, error=None):
        super(RetryHistory, self).__init__()
        self.start_time = start_time
        self.end_time = end_time
        self.code = code
        self.client_request_id = client_request_id
        self.service_request_id = service_request_id
        self.error = error
