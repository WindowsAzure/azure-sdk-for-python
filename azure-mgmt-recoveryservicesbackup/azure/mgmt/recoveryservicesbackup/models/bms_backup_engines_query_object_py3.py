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


class BMSBackupEnginesQueryObject(Model):
    """Query parameters to fetch list of backup engines.

    :param backup_management_type: Backup management type for the backup
     engine. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB', 'DPM',
     'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param friendly_name: Friendly name of the backup engine.
    :type friendly_name: str
    :param expand: Attribute to add extended info.
    :type expand: str
    """

    _attribute_map = {
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'friendly_name': {'key': 'friendlyName', 'type': 'str'},
        'expand': {'key': 'expand', 'type': 'str'},
    }

    def __init__(self, *, backup_management_type=None, friendly_name: str=None, expand: str=None, **kwargs) -> None:
        super(BMSBackupEnginesQueryObject, self).__init__(**kwargs)
        self.backup_management_type = backup_management_type
        self.friendly_name = friendly_name
        self.expand = expand
