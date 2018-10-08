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


class NetworkRuleSet(Model):
    """A set of rules governing the network accessibility of a vault.

    :param bypass: Tells what traffic can bypass network rules. This can be
     'AzureServices' or 'None'.  If not specified the default is
     'AzureServices'. Possible values include: 'AzureServices', 'None'
    :type bypass: str or
     ~azure.mgmt.keyvault.v2018_02_14.models.NetworkRuleBypassOptions
    :param default_action: The default action when no rule from ipRules and
     from virtualNetworkRules match. This is only used after the bypass
     property has been evaluated. Possible values include: 'Allow', 'Deny'
    :type default_action: str or
     ~azure.mgmt.keyvault.v2018_02_14.models.NetworkRuleAction
    :param ip_rules: The list of IP address rules.
    :type ip_rules: list[~azure.mgmt.keyvault.v2018_02_14.models.IPRule]
    :param virtual_network_rules: The list of virtual network rules.
    :type virtual_network_rules:
     list[~azure.mgmt.keyvault.v2018_02_14.models.VirtualNetworkRule]
    """

    _attribute_map = {
        'bypass': {'key': 'bypass', 'type': 'str'},
        'default_action': {'key': 'defaultAction', 'type': 'str'},
        'ip_rules': {'key': 'ipRules', 'type': '[IPRule]'},
        'virtual_network_rules': {'key': 'virtualNetworkRules', 'type': '[VirtualNetworkRule]'},
    }

    def __init__(self, *, bypass=None, default_action=None, ip_rules=None, virtual_network_rules=None, **kwargs) -> None:
        super(NetworkRuleSet, self).__init__(**kwargs)
        self.bypass = bypass
        self.default_action = default_action
        self.ip_rules = ip_rules
        self.virtual_network_rules = virtual_network_rules
