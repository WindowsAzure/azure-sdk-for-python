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

from .backup_engine_base import BackupEngineBase


class AzureBackupServerEngine(BackupEngineBase):
    """Backup engine type when Azure Backup Server is used to manage the backups.

    All required parameters must be populated in order to send to Azure.

    :param friendly_name: Friendly name of the backup engine.
    :type friendly_name: str
    :param backup_management_type: Type of backup management for the backup
     engine. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB', 'DPM',
     'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param registration_status: Registration status of the backup engine with
     the Recovery Services Vault.
    :type registration_status: str
    :param backup_engine_state: Status of the backup engine with the Recovery
     Services Vault. = {Active/Deleting/DeleteFailed}
    :type backup_engine_state: str
    :param health_status: Backup status of the backup engine.
    :type health_status: str
    :param can_re_register: Flag indicating if the backup engine be
     registered, once already registered.
    :type can_re_register: bool
    :param backup_engine_id: ID of the backup engine.
    :type backup_engine_id: str
    :param dpm_version: Backup engine version
    :type dpm_version: str
    :param azure_backup_agent_version: Backup agent version
    :type azure_backup_agent_version: str
    :param is_azure_backup_agent_upgrade_available: To check if backup agent
     upgrade available
    :type is_azure_backup_agent_upgrade_available: bool
    :param is_dpm_upgrade_available: To check if backup engine upgrade
     available
    :type is_dpm_upgrade_available: bool
    :param extended_info: Extended info of the backup engine
    :type extended_info:
     ~azure.mgmt.recoveryservicesbackup.models.BackupEngineExtendedInfo
    :param backup_engine_type: Required. Constant filled by server.
    :type backup_engine_type: str
    """

    _validation = {
        'backup_engine_type': {'required': True},
    }

    _attribute_map = {
        'friendly_name': {'key': 'friendlyName', 'type': 'str'},
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'registration_status': {'key': 'registrationStatus', 'type': 'str'},
        'backup_engine_state': {'key': 'backupEngineState', 'type': 'str'},
        'health_status': {'key': 'healthStatus', 'type': 'str'},
        'can_re_register': {'key': 'canReRegister', 'type': 'bool'},
        'backup_engine_id': {'key': 'backupEngineId', 'type': 'str'},
        'dpm_version': {'key': 'dpmVersion', 'type': 'str'},
        'azure_backup_agent_version': {'key': 'azureBackupAgentVersion', 'type': 'str'},
        'is_azure_backup_agent_upgrade_available': {'key': 'isAzureBackupAgentUpgradeAvailable', 'type': 'bool'},
        'is_dpm_upgrade_available': {'key': 'isDpmUpgradeAvailable', 'type': 'bool'},
        'extended_info': {'key': 'extendedInfo', 'type': 'BackupEngineExtendedInfo'},
        'backup_engine_type': {'key': 'backupEngineType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AzureBackupServerEngine, self).__init__(**kwargs)
        self.backup_engine_type = 'AzureBackupServerEngine'
