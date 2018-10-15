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


class ManagedRuleSets(Model):
    """Defines ManagedRuleSets - array of managedRuleSet.

    :param rule_sets: List of rules
    :type rule_sets: list[~azure.mgmt.frontdoor.models.ManagedRuleSet]
    """

    _attribute_map = {
        'rule_sets': {'key': 'ruleSets', 'type': '[ManagedRuleSet]'},
    }

    def __init__(self, *, rule_sets=None, **kwargs) -> None:
        super(ManagedRuleSets, self).__init__(**kwargs)
        self.rule_sets = rule_sets
