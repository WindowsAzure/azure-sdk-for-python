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


class ProtectionContainer(Model):
    """Base class for container with backup items. Containers with specific
    workloads are derived from this class.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AzureBackupServerContainer, AzureSqlContainer,
    DpmContainer, IaaSVMContainer, MabContainer

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
    """

    _validation = {
        'container_type': {'readonly': True},
        'protectable_object_type': {'required': True},
    }

    _attribute_map = {
        'friendly_name': {'key': 'friendlyName', 'type': 'str'},
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'registration_status': {'key': 'registrationStatus', 'type': 'str'},
        'health_status': {'key': 'healthStatus', 'type': 'str'},
        'container_type': {'key': 'containerType', 'type': 'str'},
        'protectable_object_type': {'key': 'protectableObjectType', 'type': 'str'},
    }

    _subtype_map = {
        'protectable_object_type': {'AzureBackupServerContainer': 'AzureBackupServerContainer', 'AzureSqlContainer': 'AzureSqlContainer', 'DPMContainer': 'DpmContainer', 'IaaSVMContainer': 'IaaSVMContainer', 'MABWindowsContainer': 'MabContainer'}
    }

    def __init__(self, friendly_name=None, backup_management_type=None, registration_status=None, health_status=None):
        super(ProtectionContainer, self).__init__()
        self.friendly_name = friendly_name
        self.backup_management_type = backup_management_type
        self.registration_status = registration_status
        self.health_status = health_status
        self.container_type = None
        self.protectable_object_type = None
