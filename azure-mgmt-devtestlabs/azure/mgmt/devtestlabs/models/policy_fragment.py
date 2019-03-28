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

from .update_resource import UpdateResource


class PolicyFragment(UpdateResource):
    """A Policy.

    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param description: The description of the policy.
    :type description: str
    :param status: The status of the policy. Possible values include:
     'Enabled', 'Disabled'
    :type status: str or ~azure.mgmt.devtestlabs.models.PolicyStatus
    :param fact_name: The fact name of the policy (e.g. LabVmCount, LabVmSize,
     MaxVmsAllowedPerLab, etc. Possible values include: 'UserOwnedLabVmCount',
     'UserOwnedLabPremiumVmCount', 'LabVmCount', 'LabPremiumVmCount',
     'LabVmSize', 'GalleryImage', 'UserOwnedLabVmCountInSubnet',
     'LabTargetCost', 'EnvironmentTemplate', 'ScheduleEditPermission'
    :type fact_name: str or ~azure.mgmt.devtestlabs.models.PolicyFactName
    :param fact_data: The fact data of the policy.
    :type fact_data: str
    :param threshold: The threshold of the policy (i.e. a number for
     MaxValuePolicy, and a JSON array of values for AllowedValuesPolicy).
    :type threshold: str
    :param evaluator_type: The evaluator type of the policy (i.e.
     AllowedValuesPolicy, MaxValuePolicy). Possible values include:
     'AllowedValuesPolicy', 'MaxValuePolicy'
    :type evaluator_type: str or
     ~azure.mgmt.devtestlabs.models.PolicyEvaluatorType
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'fact_name': {'key': 'properties.factName', 'type': 'str'},
        'fact_data': {'key': 'properties.factData', 'type': 'str'},
        'threshold': {'key': 'properties.threshold', 'type': 'str'},
        'evaluator_type': {'key': 'properties.evaluatorType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PolicyFragment, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.status = kwargs.get('status', None)
        self.fact_name = kwargs.get('fact_name', None)
        self.fact_data = kwargs.get('fact_data', None)
        self.threshold = kwargs.get('threshold', None)
        self.evaluator_type = kwargs.get('evaluator_type', None)
