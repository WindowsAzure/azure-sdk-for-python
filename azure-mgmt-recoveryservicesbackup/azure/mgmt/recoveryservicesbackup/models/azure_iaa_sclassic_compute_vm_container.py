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

from .iaa_svm_container import IaaSVMContainer


class AzureIaaSClassicComputeVMContainer(IaaSVMContainer):
    """IaaS VM workload-specific backup item representing a classic virtual
    machine.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param friendly_name: Friendly name of the container.
    :type friendly_name: str
    :param backup_management_type: Type of backup managemenent for the
     container. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB',
     'DPM', 'AzureBackupServer', 'AzureSql'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param registration_status: Status of registration of the container with
     the Recovery Services Vault.
    :type registration_status: str
    :param health_status: Status of health of the container.
    :type health_status: str
    :ivar container_type: Type of the container. The value of this property
     for: 1. Compute Azure VM is Microsoft.Compute/virtualMachines 2. Classic
     Compute Azure VM is Microsoft.ClassicCompute/virtualMachines 3. Windows
     machines (like MAB, DPM etc) is Windows 4. Azure SQL instance is
     AzureSqlContainer. Possible values include: 'Invalid', 'Unknown',
     'IaasVMContainer', 'IaasVMServiceContainer', 'DPMContainer',
     'AzureBackupServerContainer', 'MABContainer', 'Cluster',
     'AzureSqlContainer', 'Windows', 'VCenter'
    :vartype container_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.ContainerType
    :param protectable_object_type: Constant filled by server.
    :type protectable_object_type: str
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
        'container_type': {'readonly': True},
        'protectable_object_type': {'required': True},
    }

    def __init__(self, friendly_name=None, backup_management_type=None, registration_status=None, health_status=None, virtual_machine_id=None, virtual_machine_version=None, resource_group=None):
        super(AzureIaaSClassicComputeVMContainer, self).__init__(friendly_name=friendly_name, backup_management_type=backup_management_type, registration_status=registration_status, health_status=health_status, virtual_machine_id=virtual_machine_id, virtual_machine_version=virtual_machine_version, resource_group=resource_group)
        self.protectable_object_type = 'Microsoft.ClassicCompute/virtualMachines'
