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


class AutoHealTriggers(Model):
    """Triggers for auto-heal.

    :param requests: A rule based on total requests.
    :type requests: ~azure.mgmt.web.models.RequestsBasedTrigger
    :param private_bytes_in_kb: A rule based on private bytes.
    :type private_bytes_in_kb: int
    :param status_codes: A rule based on status codes.
    :type status_codes: list[~azure.mgmt.web.models.StatusCodesBasedTrigger]
    :param slow_requests: A rule based on request execution time.
    :type slow_requests: ~azure.mgmt.web.models.SlowRequestsBasedTrigger
    """

    _attribute_map = {
        'requests': {'key': 'requests', 'type': 'RequestsBasedTrigger'},
        'private_bytes_in_kb': {'key': 'privateBytesInKB', 'type': 'int'},
        'status_codes': {'key': 'statusCodes', 'type': '[StatusCodesBasedTrigger]'},
        'slow_requests': {'key': 'slowRequests', 'type': 'SlowRequestsBasedTrigger'},
    }

    def __init__(self, requests=None, private_bytes_in_kb=None, status_codes=None, slow_requests=None):
        self.requests = requests
        self.private_bytes_in_kb = private_bytes_in_kb
        self.status_codes = status_codes
        self.slow_requests = slow_requests
