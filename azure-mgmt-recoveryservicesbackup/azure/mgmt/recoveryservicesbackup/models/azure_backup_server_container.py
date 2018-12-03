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

from .protection_container import ProtectionContainer


class AzureBackupServerContainer(ProtectionContainer):
    """AzureBackupServer (DPMVenus) workload-specific protection container.

    All required parameters must be populated in order to send to Azure.

    :param friendly_name: Friendly name of the container.
    :type friendly_name: str
    :param backup_management_type: Type of backup management for the
     container. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB',
     'DPM', 'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param registration_status: Status of registration of the container with
     the Recovery Services Vault.
    :type registration_status: str
    :param health_status: Status of health of the container.
    :type health_status: str
    :param container_type: Required. Constant filled by server.
    :type container_type: str
    :param can_re_register: Specifies whether the container is re-registrable.
    :type can_re_register: bool
    :param container_id: ID of container.
    :type container_id: str
    :param protected_item_count: Number of protected items in the BackupEngine
    :type protected_item_count: long
    :param dpm_agent_version: Backup engine Agent version
    :type dpm_agent_version: str
    :param dpm_servers: List of BackupEngines protecting the container
    :type dpm_servers: list[str]
    :param upgrade_available: To check if upgrade available
    :type upgrade_available: bool
    :param protection_status: Protection status of the container.
    :type protection_status: str
    :param extended_info: Extended Info of the container.
    :type extended_info:
     ~azure.mgmt.recoveryservicesbackup.models.DPMContainerExtendedInfo
    """

    _validation = {
        'container_type': {'required': True},
    }

    _attribute_map = {
        'friendly_name': {'key': 'friendlyName', 'type': 'str'},
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'registration_status': {'key': 'registrationStatus', 'type': 'str'},
        'health_status': {'key': 'healthStatus', 'type': 'str'},
        'container_type': {'key': 'containerType', 'type': 'str'},
        'can_re_register': {'key': 'canReRegister', 'type': 'bool'},
        'container_id': {'key': 'containerId', 'type': 'str'},
        'protected_item_count': {'key': 'protectedItemCount', 'type': 'long'},
        'dpm_agent_version': {'key': 'dpmAgentVersion', 'type': 'str'},
        'dpm_servers': {'key': 'dpmServers', 'type': '[str]'},
        'upgrade_available': {'key': 'upgradeAvailable', 'type': 'bool'},
        'protection_status': {'key': 'protectionStatus', 'type': 'str'},
        'extended_info': {'key': 'extendedInfo', 'type': 'DPMContainerExtendedInfo'},
    }

    def __init__(self, **kwargs):
        super(AzureBackupServerContainer, self).__init__(**kwargs)
        self.can_re_register = kwargs.get('can_re_register', None)
        self.container_id = kwargs.get('container_id', None)
        self.protected_item_count = kwargs.get('protected_item_count', None)
        self.dpm_agent_version = kwargs.get('dpm_agent_version', None)
        self.dpm_servers = kwargs.get('dpm_servers', None)
        self.upgrade_available = kwargs.get('upgrade_available', None)
        self.protection_status = kwargs.get('protection_status', None)
        self.extended_info = kwargs.get('extended_info', None)
        self.container_type = 'AzureBackupServerContainer'
