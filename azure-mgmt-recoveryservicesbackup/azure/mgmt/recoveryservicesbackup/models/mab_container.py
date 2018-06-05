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


class MabContainer(ProtectionContainer):
    """Container with items backed up using MAB backup engine.

    All required parameters must be populated in order to send to Azure.

    :param friendly_name: Friendly name of the container.
    :type friendly_name: str
    :param backup_management_type: Type of backup managemenent for the
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
    :param can_re_register: Can the container be registered one more time.
    :type can_re_register: bool
    :param container_id: ContainerID represents the container.
    :type container_id: long
    :param protected_item_count: Number of items backed up in this container.
    :type protected_item_count: long
    :param agent_version: Agent version of this container.
    :type agent_version: str
    :param extended_info: Additional information for this container
    :type extended_info:
     ~azure.mgmt.recoveryservicesbackup.models.MabContainerExtendedInfo
    :param mab_container_health_details: Health details on this mab container.
    :type mab_container_health_details:
     list[~azure.mgmt.recoveryservicesbackup.models.MABContainerHealthDetails]
    :param container_health_state: Health state of mab container.
    :type container_health_state: str
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
        'container_id': {'key': 'containerId', 'type': 'long'},
        'protected_item_count': {'key': 'protectedItemCount', 'type': 'long'},
        'agent_version': {'key': 'agentVersion', 'type': 'str'},
        'extended_info': {'key': 'extendedInfo', 'type': 'MabContainerExtendedInfo'},
        'mab_container_health_details': {'key': 'mabContainerHealthDetails', 'type': '[MABContainerHealthDetails]'},
        'container_health_state': {'key': 'containerHealthState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(MabContainer, self).__init__(**kwargs)
        self.can_re_register = kwargs.get('can_re_register', None)
        self.container_id = kwargs.get('container_id', None)
        self.protected_item_count = kwargs.get('protected_item_count', None)
        self.agent_version = kwargs.get('agent_version', None)
        self.extended_info = kwargs.get('extended_info', None)
        self.mab_container_health_details = kwargs.get('mab_container_health_details', None)
        self.container_health_state = kwargs.get('container_health_state', None)
        self.container_type = 'MABWindowsContainer'
