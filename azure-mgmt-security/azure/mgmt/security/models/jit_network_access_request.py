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


class JitNetworkAccessRequest(Model):
    """JitNetworkAccessRequest.

    All required parameters must be populated in order to send to Azure.

    :param virtual_machines: Required.
    :type virtual_machines:
     list[~azure.mgmt.security.models.JitNetworkAccessRequestVirtualMachine]
    :param start_time_utc: Required. The start time of the request in UTC
    :type start_time_utc: datetime
    :param requestor: Required. The identity of the person who made the
     request
    :type requestor: str
    """

    _validation = {
        'virtual_machines': {'required': True},
        'start_time_utc': {'required': True},
        'requestor': {'required': True},
    }

    _attribute_map = {
        'virtual_machines': {'key': 'virtualMachines', 'type': '[JitNetworkAccessRequestVirtualMachine]'},
        'start_time_utc': {'key': 'startTimeUtc', 'type': 'iso-8601'},
        'requestor': {'key': 'requestor', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(JitNetworkAccessRequest, self).__init__(**kwargs)
        self.virtual_machines = kwargs.get('virtual_machines', None)
        self.start_time_utc = kwargs.get('start_time_utc', None)
        self.requestor = kwargs.get('requestor', None)
