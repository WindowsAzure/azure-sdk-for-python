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

from .retention_policy import RetentionPolicy


class SimpleRetentionPolicy(RetentionPolicy):
    """Simple policy retention.

    :param retention_policy_type: Polymorphic Discriminator
    :type retention_policy_type: str
    :param retention_duration: Retention duration of the protection policy.
    :type retention_duration: :class:`RetentionDuration
     <azure.mgmt.recoveryservicesbackup.models.RetentionDuration>`
    """

    _validation = {
        'retention_policy_type': {'required': True},
    }

    _attribute_map = {
        'retention_policy_type': {'key': 'retentionPolicyType', 'type': 'str'},
        'retention_duration': {'key': 'retentionDuration', 'type': 'RetentionDuration'},
    }

    def __init__(self, retention_duration=None):
        super(SimpleRetentionPolicy, self).__init__()
        self.retention_duration = retention_duration
        self.retention_policy_type = 'SimpleRetentionPolicy'
