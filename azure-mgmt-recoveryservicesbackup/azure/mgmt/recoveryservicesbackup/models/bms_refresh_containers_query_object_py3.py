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


class BMSRefreshContainersQueryObject(Model):
    """The query filters that can be used with the list containers API.

    :param backup_management_type: Backup management type for this container.
     Possible values include: 'Invalid', 'AzureIaasVM', 'MAB', 'DPM',
     'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    """

    _attribute_map = {
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
    }

    def __init__(self, *, backup_management_type=None, **kwargs) -> None:
        super(BMSRefreshContainersQueryObject, self).__init__(**kwargs)
        self.backup_management_type = backup_management_type
