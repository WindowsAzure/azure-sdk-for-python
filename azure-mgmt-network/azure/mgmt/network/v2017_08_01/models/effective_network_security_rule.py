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


class EffectiveNetworkSecurityRule(Model):
    """Effective network security rules.

    :param name: The name of the security rule specified by the user (if
     created by the user).
    :type name: str
    :param protocol: The network protocol this rule applies to. Possible
     values are: 'Tcp', 'Udp', and 'All'. Possible values include: 'Tcp',
     'Udp', 'All'
    :type protocol: str or
     ~azure.mgmt.network.v2017_08_01.models.EffectiveSecurityRuleProtocol
    :param source_port_range: The source port or range.
    :type source_port_range: str
    :param destination_port_range: The destination port or range.
    :type destination_port_range: str
    :param source_port_ranges: The source port ranges. Expected values include
     a single integer between 0 and 65535, a range using '-' as separator (e.g.
     100-400), or an asterisk (*)
    :type source_port_ranges: list[str]
    :param destination_port_ranges: The destination port ranges. Expected
     values include a single integer between 0 and 65535, a range using '-' as
     separator (e.g. 100-400), or an asterisk (*)
    :type destination_port_ranges: list[str]
    :param source_address_prefix: The source address prefix.
    :type source_address_prefix: str
    :param destination_address_prefix: The destination address prefix.
    :type destination_address_prefix: str
    :param source_address_prefixes: The source address prefixes. Expected
     values include CIDR IP ranges, Default Tags (VirtualNetwork,
     AzureLoadBalancer, Internet), System Tags, and the asterisk (*).
    :type source_address_prefixes: list[str]
    :param destination_address_prefixes: The destination address prefixes.
     Expected values include CIDR IP ranges, Default Tags (VirtualNetwork,
     AzureLoadBalancer, Internet), System Tags, and the asterisk (*).
    :type destination_address_prefixes: list[str]
    :param expanded_source_address_prefix: The expanded source address prefix.
    :type expanded_source_address_prefix: list[str]
    :param expanded_destination_address_prefix: Expanded destination address
     prefix.
    :type expanded_destination_address_prefix: list[str]
    :param access: Whether network traffic is allowed or denied. Possible
     values are: 'Allow' and 'Deny'. Possible values include: 'Allow', 'Deny'
    :type access: str or
     ~azure.mgmt.network.v2017_08_01.models.SecurityRuleAccess
    :param priority: The priority of the rule.
    :type priority: int
    :param direction: The direction of the rule. Possible values are: 'Inbound
     and Outbound'. Possible values include: 'Inbound', 'Outbound'
    :type direction: str or
     ~azure.mgmt.network.v2017_08_01.models.SecurityRuleDirection
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'protocol': {'key': 'protocol', 'type': 'str'},
        'source_port_range': {'key': 'sourcePortRange', 'type': 'str'},
        'destination_port_range': {'key': 'destinationPortRange', 'type': 'str'},
        'source_port_ranges': {'key': 'sourcePortRanges', 'type': '[str]'},
        'destination_port_ranges': {'key': 'destinationPortRanges', 'type': '[str]'},
        'source_address_prefix': {'key': 'sourceAddressPrefix', 'type': 'str'},
        'destination_address_prefix': {'key': 'destinationAddressPrefix', 'type': 'str'},
        'source_address_prefixes': {'key': 'sourceAddressPrefixes', 'type': '[str]'},
        'destination_address_prefixes': {'key': 'destinationAddressPrefixes', 'type': '[str]'},
        'expanded_source_address_prefix': {'key': 'expandedSourceAddressPrefix', 'type': '[str]'},
        'expanded_destination_address_prefix': {'key': 'expandedDestinationAddressPrefix', 'type': '[str]'},
        'access': {'key': 'access', 'type': 'str'},
        'priority': {'key': 'priority', 'type': 'int'},
        'direction': {'key': 'direction', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EffectiveNetworkSecurityRule, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.protocol = kwargs.get('protocol', None)
        self.source_port_range = kwargs.get('source_port_range', None)
        self.destination_port_range = kwargs.get('destination_port_range', None)
        self.source_port_ranges = kwargs.get('source_port_ranges', None)
        self.destination_port_ranges = kwargs.get('destination_port_ranges', None)
        self.source_address_prefix = kwargs.get('source_address_prefix', None)
        self.destination_address_prefix = kwargs.get('destination_address_prefix', None)
        self.source_address_prefixes = kwargs.get('source_address_prefixes', None)
        self.destination_address_prefixes = kwargs.get('destination_address_prefixes', None)
        self.expanded_source_address_prefix = kwargs.get('expanded_source_address_prefix', None)
        self.expanded_destination_address_prefix = kwargs.get('expanded_destination_address_prefix', None)
        self.access = kwargs.get('access', None)
        self.priority = kwargs.get('priority', None)
        self.direction = kwargs.get('direction', None)
