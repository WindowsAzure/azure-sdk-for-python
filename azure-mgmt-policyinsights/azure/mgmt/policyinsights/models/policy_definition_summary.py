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


class PolicyDefinitionSummary(Model):
    """Policy definition summary.

    :param policy_definition_id: Policy definition ID.
    :type policy_definition_id: str
    :param policy_definition_reference_id: Policy definition reference ID.
    :type policy_definition_reference_id: str
    :param effect: Policy effect, i.e. policy definition action.
    :type effect: str
    :param results: Non-compliance summary for the policy definition.
    :type results: ~azure.mgmt.policyinsights.models.SummaryResults
    """

    _attribute_map = {
        'policy_definition_id': {'key': 'policyDefinitionId', 'type': 'str'},
        'policy_definition_reference_id': {'key': 'policyDefinitionReferenceId', 'type': 'str'},
        'effect': {'key': 'effect', 'type': 'str'},
        'results': {'key': 'results', 'type': 'SummaryResults'},
    }

    def __init__(self, **kwargs):
        super(PolicyDefinitionSummary, self).__init__(**kwargs)
        self.policy_definition_id = kwargs.get('policy_definition_id', None)
        self.policy_definition_reference_id = kwargs.get('policy_definition_reference_id', None)
        self.effect = kwargs.get('effect', None)
        self.results = kwargs.get('results', None)
