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


class IPRule(Model):
    """IP rule with specific IP or IP range in CIDR format.

    All required parameters must be populated in order to send to Azure.

    :param ip_address_or_range: Required. Specifies the IP or IP range in CIDR
     format. Only IPV4 address is allowed.
    :type ip_address_or_range: str
    :param action: The action of IP ACL rule. Possible values include:
     'Allow'. Default value: "Allow" .
    :type action: str or ~azure.mgmt.storage.v2018_02_01.models.Action
    """

    _validation = {
        'ip_address_or_range': {'required': True},
    }

    _attribute_map = {
        'ip_address_or_range': {'key': 'value', 'type': 'str'},
        'action': {'key': 'action', 'type': 'Action'},
    }

    def __init__(self, **kwargs):
        super(IPRule, self).__init__(**kwargs)
        self.ip_address_or_range = kwargs.get('ip_address_or_range', None)
        self.action = kwargs.get('action', "Allow")
