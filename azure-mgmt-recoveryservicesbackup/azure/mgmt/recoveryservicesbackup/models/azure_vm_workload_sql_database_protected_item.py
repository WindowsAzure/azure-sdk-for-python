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

from .protected_item import ProtectedItem


class AzureVmWorkloadSQLDatabaseProtectedItem(ProtectedItem):
    """Azure VM workload-specific protected item representing SQL Database.

    :param backup_management_type: Type of backup managemenent for the backed
     up item. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB', 'DPM',
     'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param workload_type: Type of workload this item represents. Possible
     values include: 'Invalid', 'VM', 'FileFolder', 'AzureSqlDb', 'SQLDB',
     'Exchange', 'Sharepoint', 'VMwareVM', 'SystemState', 'Client',
     'GenericDataSource', 'SQLDataBase', 'AzureFileShare'
    :type workload_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.DataSourceType
    :param container_name: Unique name of container
    :type container_name: str
    :param source_resource_id: ARM ID of the resource to be backed up.
    :type source_resource_id: str
    :param policy_id: ID of the backup policy with which this item is backed
     up.
    :type policy_id: str
    :param last_recovery_point: Timestamp when the last (latest) backup copy
     was created for this backup item.
    :type last_recovery_point: datetime
    :param backup_set_name: Name of the backup set the backup item belongs to
    :type backup_set_name: str
    :param protected_item_type: Constant filled by server.
    :type protected_item_type: str
    :param friendly_name: Friendly name of the DB represented by this backup
     item.
    :type friendly_name: str
    :param server_name: Host/Cluster Name for instance or AG
    :type server_name: str
    :param parent_name: Parent name of the DB such as Instance or Availability
     Group.
    :type parent_name: str
    :param parent_type: Parent type of DB, SQLAG or StandAlone
    :type parent_type: str
    :param protection_status: Backup status of this backup item.
    :type protection_status: str
    :param protection_state: Backup state of this backup item. Possible values
     include: 'Invalid', 'IRPending', 'Protected', 'ProtectionError',
     'ProtectionStopped', 'ProtectionPaused'
    :type protection_state: str or
     ~azure.mgmt.recoveryservicesbackup.models.ProtectionState
    :param last_backup_status: Last backup operation status. Possible values:
     Healthy, Unhealthy. Possible values include: 'Invalid', 'Healthy',
     'Unhealthy', 'IRPending'
    :type last_backup_status: str or
     ~azure.mgmt.recoveryservicesbackup.models.LastBackupStatus
    :param last_backup_time: Timestamp of the last backup operation on this
     backup item.
    :type last_backup_time: datetime
    :param last_backup_error_detail: Error details in last backup
    :type last_backup_error_detail:
     ~azure.mgmt.recoveryservicesbackup.models.ErrorDetail
    :param protected_item_data_source_id: Data ID of the protected item.
    :type protected_item_data_source_id: str
    :param protected_item_health_status: Health status of the backup item,
     evaluated based on last heartbeat received. Possible values include:
     'Invalid', 'Healthy', 'Unhealthy', 'NotReachable', 'IRPending'
    :type protected_item_health_status: str or
     ~azure.mgmt.recoveryservicesbackup.models.ProtectedItemHealthStatus
    :param extended_info: Additional information for this backup item.
    :type extended_info:
     ~azure.mgmt.recoveryservicesbackup.models.AzureVmWorkloadProtectedItemExtendedInfo
    """

    _validation = {
        'protected_item_type': {'required': True},
    }

    _attribute_map = {
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'workload_type': {'key': 'workloadType', 'type': 'str'},
        'container_name': {'key': 'containerName', 'type': 'str'},
        'source_resource_id': {'key': 'sourceResourceId', 'type': 'str'},
        'policy_id': {'key': 'policyId', 'type': 'str'},
        'last_recovery_point': {'key': 'lastRecoveryPoint', 'type': 'iso-8601'},
        'backup_set_name': {'key': 'backupSetName', 'type': 'str'},
        'protected_item_type': {'key': 'protectedItemType', 'type': 'str'},
        'friendly_name': {'key': 'friendlyName', 'type': 'str'},
        'server_name': {'key': 'serverName', 'type': 'str'},
        'parent_name': {'key': 'parentName', 'type': 'str'},
        'parent_type': {'key': 'parentType', 'type': 'str'},
        'protection_status': {'key': 'protectionStatus', 'type': 'str'},
        'protection_state': {'key': 'protectionState', 'type': 'str'},
        'last_backup_status': {'key': 'lastBackupStatus', 'type': 'str'},
        'last_backup_time': {'key': 'lastBackupTime', 'type': 'iso-8601'},
        'last_backup_error_detail': {'key': 'lastBackupErrorDetail', 'type': 'ErrorDetail'},
        'protected_item_data_source_id': {'key': 'protectedItemDataSourceId', 'type': 'str'},
        'protected_item_health_status': {'key': 'protectedItemHealthStatus', 'type': 'str'},
        'extended_info': {'key': 'extendedInfo', 'type': 'AzureVmWorkloadProtectedItemExtendedInfo'},
    }

    def __init__(self, backup_management_type=None, workload_type=None, container_name=None, source_resource_id=None, policy_id=None, last_recovery_point=None, backup_set_name=None, friendly_name=None, server_name=None, parent_name=None, parent_type=None, protection_status=None, protection_state=None, last_backup_status=None, last_backup_time=None, last_backup_error_detail=None, protected_item_data_source_id=None, protected_item_health_status=None, extended_info=None):
        super(AzureVmWorkloadSQLDatabaseProtectedItem, self).__init__(backup_management_type=backup_management_type, workload_type=workload_type, container_name=container_name, source_resource_id=source_resource_id, policy_id=policy_id, last_recovery_point=last_recovery_point, backup_set_name=backup_set_name)
        self.friendly_name = friendly_name
        self.server_name = server_name
        self.parent_name = parent_name
        self.parent_type = parent_type
        self.protection_status = protection_status
        self.protection_state = protection_state
        self.last_backup_status = last_backup_status
        self.last_backup_time = last_backup_time
        self.last_backup_error_detail = last_backup_error_detail
        self.protected_item_data_source_id = protected_item_data_source_id
        self.protected_item_health_status = protected_item_health_status
        self.extended_info = extended_info
        self.protected_item_type = 'AzureVmWorkloadSQLDatabase'
