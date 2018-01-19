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

from .protection_intent import ProtectionIntent


class AzureResourceProtectionIntent(ProtectionIntent):
    """IaaS VM specific backup protection intent item.

    :param backup_management_type: Type of backup managemenent for the backed
     up item. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB', 'DPM',
     'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param source_resource_id: ARM ID of the resource to be backed up.
    :type source_resource_id: str
    :param item_id: ID of the item which is getting protected, In case of
     Azure Vm , it is ProtectedItemId
    :type item_id: str
    :param policy_id: ID of the backup policy with which this item is backed
     up.
    :type policy_id: str
    :param protection_state: Backup state of this backup item. Possible values
     include: 'Invalid', 'NotProtected', 'Protecting', 'Protected',
     'ProtectionFailed'
    :type protection_state: str or
     ~azure.mgmt.recoveryservicesbackup.models.ProtectionStatus
    :param protection_intent_item_type: Constant filled by server.
    :type protection_intent_item_type: str
    :param friendly_name: Friendly name of the VM represented by this backup
     item.
    :type friendly_name: str
    """

    _validation = {
        'protection_intent_item_type': {'required': True},
    }

    _attribute_map = {
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'source_resource_id': {'key': 'sourceResourceId', 'type': 'str'},
        'item_id': {'key': 'itemId', 'type': 'str'},
        'policy_id': {'key': 'policyId', 'type': 'str'},
        'protection_state': {'key': 'protectionState', 'type': 'str'},
        'protection_intent_item_type': {'key': 'protectionIntentItemType', 'type': 'str'},
        'friendly_name': {'key': 'friendlyName', 'type': 'str'},
    }

    def __init__(self, backup_management_type=None, source_resource_id=None, item_id=None, policy_id=None, protection_state=None, friendly_name=None):
        super(AzureResourceProtectionIntent, self).__init__(backup_management_type=backup_management_type, source_resource_id=source_resource_id, item_id=item_id, policy_id=policy_id, protection_state=protection_state)
        self.friendly_name = friendly_name
        self.protection_intent_item_type = 'AzureResourceItem'
