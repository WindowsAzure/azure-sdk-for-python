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


class DpmBackupEngine(BackupEngineBase):
    """Data Protection Manager (DPM) specific backup engine.

    :param friendly_name: Friendly name of the backup engine.
    :type friendly_name: str
    :param backup_management_type: Type of backup management for the backup
     engine. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB', 'DPM',
     'AzureBackupServer', 'AzureSql'
    :type backup_management_type: str or :class:`BackupManagementType
     <azure.mgmt.recoveryservicesbackup.models.BackupManagementType>`
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
    :param extended_info: Extended info of the backupengine
    :type extended_info: :class:`BackupEngineExtendedInfo
     <azure.mgmt.recoveryservicesbackup.models.BackupEngineExtendedInfo>`
    :param backup_engine_type: Polymorphic Discriminator
    :type backup_engine_type: str
    """

    _validation = {
        'backup_engine_type': {'required': True},
    }

    def __init__(self, friendly_name=None, backup_management_type=None, registration_status=None, backup_engine_state=None, health_status=None, can_re_register=None, backup_engine_id=None, dpm_version=None, azure_backup_agent_version=None, is_azure_backup_agent_upgrade_available=None, is_dpm_upgrade_available=None, extended_info=None):
        super(DpmBackupEngine, self).__init__(friendly_name=friendly_name, backup_management_type=backup_management_type, registration_status=registration_status, backup_engine_state=backup_engine_state, health_status=health_status, can_re_register=can_re_register, backup_engine_id=backup_engine_id, dpm_version=dpm_version, azure_backup_agent_version=azure_backup_agent_version, is_azure_backup_agent_upgrade_available=is_azure_backup_agent_upgrade_available, is_dpm_upgrade_available=is_dpm_upgrade_available, extended_info=extended_info)
        self.backup_engine_type = 'DpmBackupEngine'
