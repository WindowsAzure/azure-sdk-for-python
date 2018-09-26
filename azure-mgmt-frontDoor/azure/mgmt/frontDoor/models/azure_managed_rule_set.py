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

from .managed_rule_set import ManagedRuleSet


class AzureManagedRuleSet(ManagedRuleSet):
    """Describes azure managed provider.

    All required parameters must be populated in order to send to Azure.

    :param priority: Describes priority of the rule
    :type priority: int
    :param version: defines version of the ruleset
    :type version: int
    :param rule_set_type: Required. Constant filled by server.
    :type rule_set_type: str
    :param rule_group_overrides: List of azure managed provider override
     configuration (optional)
    :type rule_group_overrides:
     list[~azure.mgmt.frontdoor.models.AzureManagedOverrideRuleGroup]
    """

    _validation = {
        'rule_set_type': {'required': True},
    }

    _attribute_map = {
        'priority': {'key': 'priority', 'type': 'int'},
        'version': {'key': 'version', 'type': 'int'},
        'rule_set_type': {'key': 'ruleSetType', 'type': 'str'},
        'rule_group_overrides': {'key': 'ruleGroupOverrides', 'type': '[AzureManagedOverrideRuleGroup]'},
    }

    def __init__(self, **kwargs):
        super(AzureManagedRuleSet, self).__init__(**kwargs)
        self.rule_group_overrides = kwargs.get('rule_group_overrides', None)
        self.rule_set_type = 'AzureManagedRuleSet'
