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


class ApplicationGatewayFirewallRuleGroup(Model):
    """A web application firewall rule group.

    :param rule_group_name: The name of the web application firewall rule
     group.
    :type rule_group_name: str
    :param description: The description of the web application firewall rule
     group.
    :type description: str
    :param rules: The rules of the web application firewall rule group.
    :type rules:
     list[~azure.mgmt.network.v2017_06_01.models.ApplicationGatewayFirewallRule]
    """

    _validation = {
        'rule_group_name': {'required': True},
        'rules': {'required': True},
    }

    _attribute_map = {
        'rule_group_name': {'key': 'ruleGroupName', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'rules': {'key': 'rules', 'type': '[ApplicationGatewayFirewallRule]'},
    }

    def __init__(self, rule_group_name, rules, description=None):
        self.rule_group_name = rule_group_name
        self.description = description
        self.rules = rules
