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


class AzureVmWorkloadProtectedItemExtendedInfo(Model):
    """Additional information on Azure Workload for SQL specific backup item.

    :param oldest_recovery_point: The oldest backup copy available for this
     backup item.
    :type oldest_recovery_point: datetime
    :param recovery_point_count: Number of backup copies available for this
     backup item.
    :type recovery_point_count: int
    :param policy_state: Indicates consistency of policy object and policy
     applied to this backup item.
    :type policy_state: str
    """

    _attribute_map = {
        'oldest_recovery_point': {'key': 'oldestRecoveryPoint', 'type': 'iso-8601'},
        'recovery_point_count': {'key': 'recoveryPointCount', 'type': 'int'},
        'policy_state': {'key': 'policyState', 'type': 'str'},
    }

    def __init__(self, oldest_recovery_point=None, recovery_point_count=None, policy_state=None):
        super(AzureVmWorkloadProtectedItemExtendedInfo, self).__init__()
        self.oldest_recovery_point = oldest_recovery_point
        self.recovery_point_count = recovery_point_count
        self.policy_state = policy_state
