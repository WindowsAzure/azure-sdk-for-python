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


class AzureFirewallApplicationRuleProtocol(Model):
    """Properties of the application rule protocol.

    :param protocol_type: Protocol type. Possible values include: 'Http',
     'Https'
    :type protocol_type: str or
     ~azure.mgmt.network.v2018_12_01.models.AzureFirewallApplicationRuleProtocolType
    :param port: Port number for the protocol, cannot be greater than 64000.
     This field is optional.
    :type port: int
    """

    _validation = {
        'port': {'maximum': 64000, 'minimum': 0},
    }

    _attribute_map = {
        'protocol_type': {'key': 'protocolType', 'type': 'str'},
        'port': {'key': 'port', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(AzureFirewallApplicationRuleProtocol, self).__init__(**kwargs)
        self.protocol_type = kwargs.get('protocol_type', None)
        self.port = kwargs.get('port', None)
