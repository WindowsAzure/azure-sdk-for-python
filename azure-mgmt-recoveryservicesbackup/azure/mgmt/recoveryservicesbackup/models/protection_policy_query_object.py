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


class ProtectionPolicyQueryObject(Model):
    """Filters the list backup policies API.

    :param backup_management_type: Backup management type for the backup
     policy. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB', 'DPM',
     'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param fabric_name: Fabric name for filter
    :type fabric_name: str
    :param workload_type: Workload type for the backup policy. Possible values
     include: 'Invalid', 'VM', 'FileFolder', 'AzureSqlDb', 'SQLDB', 'Exchange',
     'Sharepoint', 'VMwareVM', 'SystemState', 'Client', 'GenericDataSource',
     'SQLDataBase', 'AzureFileShare', 'SAPHanaDatabase'
    :type workload_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.WorkloadType
    """

    _attribute_map = {
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'fabric_name': {'key': 'fabricName', 'type': 'str'},
        'workload_type': {'key': 'workloadType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ProtectionPolicyQueryObject, self).__init__(**kwargs)
        self.backup_management_type = kwargs.get('backup_management_type', None)
        self.fabric_name = kwargs.get('fabric_name', None)
        self.workload_type = kwargs.get('workload_type', None)
