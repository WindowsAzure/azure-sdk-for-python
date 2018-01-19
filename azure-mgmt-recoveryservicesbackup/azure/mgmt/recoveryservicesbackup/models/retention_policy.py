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


class RetentionPolicy(Model):
    """Base class for retention policy.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: LongTermRetentionPolicy, SimpleRetentionPolicy

    :param retention_policy_type: Constant filled by server.
    :type retention_policy_type: str
    """

    _validation = {
        'retention_policy_type': {'required': True},
    }

    _attribute_map = {
        'retention_policy_type': {'key': 'retentionPolicyType', 'type': 'str'},
    }

    _subtype_map = {
        'retention_policy_type': {'LongTermRetentionPolicy': 'LongTermRetentionPolicy', 'SimpleRetentionPolicy': 'SimpleRetentionPolicy'}
    }

    def __init__(self):
        super(RetentionPolicy, self).__init__()
        self.retention_policy_type = None
