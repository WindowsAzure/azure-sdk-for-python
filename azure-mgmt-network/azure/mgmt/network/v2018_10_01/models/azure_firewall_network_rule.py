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


class AzureFirewallNetworkRule(Model):
    """Properties of the network rule.

    :param name: Name of the network rule.
    :type name: str
    :param description: Description of the rule.
    :type description: str
    :param protocols: Array of AzureFirewallNetworkRuleProtocols.
    :type protocols: list[str or
     ~azure.mgmt.network.v2018_10_01.models.AzureFirewallNetworkRuleProtocol]
    :param source_addresses: List of source IP addresses for this rule.
    :type source_addresses: list[str]
    :param destination_addresses: List of destination IP addresses.
    :type destination_addresses: list[str]
    :param destination_ports: List of destination ports.
    :type destination_ports: list[str]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'protocols': {'key': 'protocols', 'type': '[str]'},
        'source_addresses': {'key': 'sourceAddresses', 'type': '[str]'},
        'destination_addresses': {'key': 'destinationAddresses', 'type': '[str]'},
        'destination_ports': {'key': 'destinationPorts', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(AzureFirewallNetworkRule, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.description = kwargs.get('description', None)
        self.protocols = kwargs.get('protocols', None)
        self.source_addresses = kwargs.get('source_addresses', None)
        self.destination_addresses = kwargs.get('destination_addresses', None)
        self.destination_ports = kwargs.get('destination_ports', None)
