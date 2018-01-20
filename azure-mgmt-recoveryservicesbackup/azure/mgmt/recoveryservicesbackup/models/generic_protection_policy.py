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

from .protection_policy import ProtectionPolicy


class GenericProtectionPolicy(ProtectionPolicy):
    """Azure VM (Mercury) workload-specific backup policy.

    :param protected_items_count: Number of items associated with this policy.
    :type protected_items_count: int
    :param backup_management_type: Constant filled by server.
    :type backup_management_type: str
    :param sub_protection_policy: List of sub-protection policies which
     includes schedule and retention
    :type sub_protection_policy:
     list[~azure.mgmt.recoveryservicesbackup.models.SubProtectionPolicy]
    :param time_zone: TimeZone optional input as string. For example: TimeZone
     = "Pacific Standard Time".
    :type time_zone: str
    :param fabric_name: Name of this policy's fabric.
    :type fabric_name: str
    """

    _validation = {
        'backup_management_type': {'required': True},
    }

    _attribute_map = {
        'protected_items_count': {'key': 'protectedItemsCount', 'type': 'int'},
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'sub_protection_policy': {'key': 'subProtectionPolicy', 'type': '[SubProtectionPolicy]'},
        'time_zone': {'key': 'timeZone', 'type': 'str'},
        'fabric_name': {'key': 'fabricName', 'type': 'str'},
    }

    def __init__(self, protected_items_count=None, sub_protection_policy=None, time_zone=None, fabric_name=None):
        super(GenericProtectionPolicy, self).__init__(protected_items_count=protected_items_count)
        self.sub_protection_policy = sub_protection_policy
        self.time_zone = time_zone
        self.fabric_name = fabric_name
        self.backup_management_type = 'GenericProtectionPolicy'
