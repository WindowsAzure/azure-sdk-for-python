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


class JitNetworkAccessPolicyInitiatePort(Model):
    """JitNetworkAccessPolicyInitiatePort.

    All required parameters must be populated in order to send to Azure.

    :param number: Required.
    :type number: int
    :param allowed_source_address_prefix: Source of the allowed traffic. If
     omitted, the request will be for the source IP address of the initiate
     request.
    :type allowed_source_address_prefix: str
    :param end_time_utc: Required. The time to close the request in UTC
    :type end_time_utc: datetime
    """

    _validation = {
        'number': {'required': True},
        'end_time_utc': {'required': True},
    }

    _attribute_map = {
        'number': {'key': 'number', 'type': 'int'},
        'allowed_source_address_prefix': {'key': 'allowedSourceAddressPrefix', 'type': 'str'},
        'end_time_utc': {'key': 'endTimeUtc', 'type': 'iso-8601'},
    }

    def __init__(self, *, number: int, end_time_utc, allowed_source_address_prefix: str=None, **kwargs) -> None:
        super(JitNetworkAccessPolicyInitiatePort, self).__init__(**kwargs)
        self.number = number
        self.allowed_source_address_prefix = allowed_source_address_prefix
        self.end_time_utc = end_time_utc
