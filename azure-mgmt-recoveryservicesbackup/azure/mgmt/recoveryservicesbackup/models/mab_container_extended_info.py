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


class MabContainerExtendedInfo(Model):
    """Additional information of the container.

    :param last_refreshed_at: Time stamp when this container was refreshed.
    :type last_refreshed_at: datetime
    :param backup_item_type: Type of backup items associated with this
     container. Possible values include: 'Invalid', 'VM', 'FileFolder',
     'AzureSqlDb', 'SQLDB', 'Exchange', 'Sharepoint', 'VMwareVM',
     'SystemState', 'Client', 'GenericDataSource', 'SQLDataBase',
     'AzureFileShare'
    :type backup_item_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupItemType
    :param backup_items: List of backup items associated with this container.
    :type backup_items: list[str]
    :param policy_name: Backup policy associated with this container.
    :type policy_name: str
    :param last_backup_status: Latest backup status of this container.
    :type last_backup_status: str
    """

    _attribute_map = {
        'last_refreshed_at': {'key': 'lastRefreshedAt', 'type': 'iso-8601'},
        'backup_item_type': {'key': 'backupItemType', 'type': 'str'},
        'backup_items': {'key': 'backupItems', 'type': '[str]'},
        'policy_name': {'key': 'policyName', 'type': 'str'},
        'last_backup_status': {'key': 'lastBackupStatus', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(MabContainerExtendedInfo, self).__init__(**kwargs)
        self.last_refreshed_at = kwargs.get('last_refreshed_at', None)
        self.backup_item_type = kwargs.get('backup_item_type', None)
        self.backup_items = kwargs.get('backup_items', None)
        self.policy_name = kwargs.get('policy_name', None)
        self.last_backup_status = kwargs.get('last_backup_status', None)
