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


class ProtectionIntentQueryObject(Model):
    """Filters to list protection intent.

    :param backup_management_type: Backup management type for the backed up
     item. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB', 'DPM',
     'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param item_type: Type of workload this item represents. Possible values
     include: 'Invalid', 'SQLInstance', 'SQLAvailabilityGroupContainer'
    :type item_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.IntentItemType
    :param parent_name: Parent name of the intent
    :type parent_name: str
    :param item_name: Item name of the intent
    :type item_name: str
    """

    _attribute_map = {
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'item_type': {'key': 'itemType', 'type': 'str'},
        'parent_name': {'key': 'parentName', 'type': 'str'},
        'item_name': {'key': 'itemName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ProtectionIntentQueryObject, self).__init__(**kwargs)
        self.backup_management_type = kwargs.get('backup_management_type', None)
        self.item_type = kwargs.get('item_type', None)
        self.parent_name = kwargs.get('parent_name', None)
        self.item_name = kwargs.get('item_name', None)
