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


class IaaSVMContainer(ProtectionContainer):
    """IaaS VM workload-specific container.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AzureIaaSClassicComputeVMContainer,
    AzureIaaSComputeVMContainer

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
    :param virtual_machine_id: Fully qualified ARM url of the virtual machine
     represented by this Azure IaaS VM container.
    :type virtual_machine_id: str
    :param virtual_machine_version: Specifies whether the container represents
     a Classic or an Azure Resource Manager VM.
    :type virtual_machine_version: str
    :param resource_group: Resource group name of Recovery Services Vault.
    :type resource_group: str
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
        'virtual_machine_id': {'key': 'virtualMachineId', 'type': 'str'},
        'virtual_machine_version': {'key': 'virtualMachineVersion', 'type': 'str'},
        'resource_group': {'key': 'resourceGroup', 'type': 'str'},
    }

    _subtype_map = {
        'container_type': {'Microsoft.ClassicCompute/virtualMachines': 'AzureIaaSClassicComputeVMContainer', 'Microsoft.Compute/virtualMachines': 'AzureIaaSComputeVMContainer'}
    }

    def __init__(self, **kwargs):
        super(IaaSVMContainer, self).__init__(**kwargs)
        self.virtual_machine_id = kwargs.get('virtual_machine_id', None)
        self.virtual_machine_version = kwargs.get('virtual_machine_version', None)
        self.resource_group = kwargs.get('resource_group', None)
        self.container_type = 'IaaSVMContainer'
