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

from .resource import Resource


class NetworkRuleSet(Resource):
    """Description of NetworkRuleSet resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param default_action: Default Action for Network Rule Set. Possible
     values include: 'Allow', 'Deny'
    :type default_action: str or ~azure.mgmt.servicebus.models.DefaultAction
    :param virtual_network_rules: List VirtualNetwork Rules
    :type virtual_network_rules:
     list[~azure.mgmt.servicebus.models.NWRuleSetVirtualNetworkRules]
    :param ip_rules: List of IpRules
    :type ip_rules: list[~azure.mgmt.servicebus.models.NWRuleSetIpRules]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'default_action': {'key': 'properties.defaultAction', 'type': 'str'},
        'virtual_network_rules': {'key': 'properties.virtualNetworkRules', 'type': '[NWRuleSetVirtualNetworkRules]'},
        'ip_rules': {'key': 'properties.ipRules', 'type': '[NWRuleSetIpRules]'},
    }

    def __init__(self, **kwargs):
        super(NetworkRuleSet, self).__init__(**kwargs)
        self.default_action = kwargs.get('default_action', None)
        self.virtual_network_rules = kwargs.get('virtual_network_rules', None)
        self.ip_rules = kwargs.get('ip_rules', None)
