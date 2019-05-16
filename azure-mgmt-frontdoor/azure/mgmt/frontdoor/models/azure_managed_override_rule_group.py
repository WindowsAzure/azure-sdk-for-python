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


class AzureManagedOverrideRuleGroup(Model):
    """Defines contents of a web application rule.

    All required parameters must be populated in order to send to Azure.

    :param rule_group_override: Required. Describes override rule group.
     Possible values include: 'SqlInjection', 'XSS'
    :type rule_group_override: str or
     ~azure.mgmt.frontdoor.models.RuleGroupOverride
    :param action: Required. Type of Actions. Possible values include:
     'Allow', 'Block', 'Log'
    :type action: str or ~azure.mgmt.frontdoor.models.Action
    """

    _validation = {
        'rule_group_override': {'required': True},
        'action': {'required': True},
    }

    _attribute_map = {
        'rule_group_override': {'key': 'ruleGroupOverride', 'type': 'str'},
        'action': {'key': 'action', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AzureManagedOverrideRuleGroup, self).__init__(**kwargs)
        self.rule_group_override = kwargs.get('rule_group_override', None)
        self.action = kwargs.get('action', None)
