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


class ManagedClusterAgentPoolProfile(Model):
    """Profile for the container service agent pool.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Unique name of the agent pool profile in the
     context of the subscription and resource group.
    :type name: str
    :param count: Number of agents (VMs) to host docker containers. Allowed
     values must be in the range of 1 to 100 (inclusive). The default value is
     1. . Default value: 1 .
    :type count: int
    :param vm_size: Required. Size of agent VMs. Possible values include:
     'Standard_A1', 'Standard_A10', 'Standard_A11', 'Standard_A1_v2',
     'Standard_A2', 'Standard_A2_v2', 'Standard_A2m_v2', 'Standard_A3',
     'Standard_A4', 'Standard_A4_v2', 'Standard_A4m_v2', 'Standard_A5',
     'Standard_A6', 'Standard_A7', 'Standard_A8', 'Standard_A8_v2',
     'Standard_A8m_v2', 'Standard_A9', 'Standard_B2ms', 'Standard_B2s',
     'Standard_B4ms', 'Standard_B8ms', 'Standard_D1', 'Standard_D11',
     'Standard_D11_v2', 'Standard_D11_v2_Promo', 'Standard_D12',
     'Standard_D12_v2', 'Standard_D12_v2_Promo', 'Standard_D13',
     'Standard_D13_v2', 'Standard_D13_v2_Promo', 'Standard_D14',
     'Standard_D14_v2', 'Standard_D14_v2_Promo', 'Standard_D15_v2',
     'Standard_D16_v3', 'Standard_D16s_v3', 'Standard_D1_v2', 'Standard_D2',
     'Standard_D2_v2', 'Standard_D2_v2_Promo', 'Standard_D2_v3',
     'Standard_D2s_v3', 'Standard_D3', 'Standard_D32_v3', 'Standard_D32s_v3',
     'Standard_D3_v2', 'Standard_D3_v2_Promo', 'Standard_D4', 'Standard_D4_v2',
     'Standard_D4_v2_Promo', 'Standard_D4_v3', 'Standard_D4s_v3',
     'Standard_D5_v2', 'Standard_D5_v2_Promo', 'Standard_D64_v3',
     'Standard_D64s_v3', 'Standard_D8_v3', 'Standard_D8s_v3', 'Standard_DS1',
     'Standard_DS11', 'Standard_DS11_v2', 'Standard_DS11_v2_Promo',
     'Standard_DS12', 'Standard_DS12_v2', 'Standard_DS12_v2_Promo',
     'Standard_DS13', 'Standard_DS13-2_v2', 'Standard_DS13-4_v2',
     'Standard_DS13_v2', 'Standard_DS13_v2_Promo', 'Standard_DS14',
     'Standard_DS14-4_v2', 'Standard_DS14-8_v2', 'Standard_DS14_v2',
     'Standard_DS14_v2_Promo', 'Standard_DS15_v2', 'Standard_DS1_v2',
     'Standard_DS2', 'Standard_DS2_v2', 'Standard_DS2_v2_Promo',
     'Standard_DS3', 'Standard_DS3_v2', 'Standard_DS3_v2_Promo',
     'Standard_DS4', 'Standard_DS4_v2', 'Standard_DS4_v2_Promo',
     'Standard_DS5_v2', 'Standard_DS5_v2_Promo', 'Standard_E16_v3',
     'Standard_E16s_v3', 'Standard_E2_v3', 'Standard_E2s_v3',
     'Standard_E32-16s_v3', 'Standard_E32-8s_v3', 'Standard_E32_v3',
     'Standard_E32s_v3', 'Standard_E4_v3', 'Standard_E4s_v3',
     'Standard_E64-16s_v3', 'Standard_E64-32s_v3', 'Standard_E64_v3',
     'Standard_E64s_v3', 'Standard_E8_v3', 'Standard_E8s_v3', 'Standard_F1',
     'Standard_F16', 'Standard_F16s', 'Standard_F16s_v2', 'Standard_F1s',
     'Standard_F2', 'Standard_F2s', 'Standard_F2s_v2', 'Standard_F32s_v2',
     'Standard_F4', 'Standard_F4s', 'Standard_F4s_v2', 'Standard_F64s_v2',
     'Standard_F72s_v2', 'Standard_F8', 'Standard_F8s', 'Standard_F8s_v2',
     'Standard_G1', 'Standard_G2', 'Standard_G3', 'Standard_G4', 'Standard_G5',
     'Standard_GS1', 'Standard_GS2', 'Standard_GS3', 'Standard_GS4',
     'Standard_GS4-4', 'Standard_GS4-8', 'Standard_GS5', 'Standard_GS5-16',
     'Standard_GS5-8', 'Standard_H16', 'Standard_H16m', 'Standard_H16mr',
     'Standard_H16r', 'Standard_H8', 'Standard_H8m', 'Standard_L16s',
     'Standard_L32s', 'Standard_L4s', 'Standard_L8s', 'Standard_M128-32ms',
     'Standard_M128-64ms', 'Standard_M128ms', 'Standard_M128s',
     'Standard_M64-16ms', 'Standard_M64-32ms', 'Standard_M64ms',
     'Standard_M64s', 'Standard_NC12', 'Standard_NC12s_v2',
     'Standard_NC12s_v3', 'Standard_NC24', 'Standard_NC24r',
     'Standard_NC24rs_v2', 'Standard_NC24rs_v3', 'Standard_NC24s_v2',
     'Standard_NC24s_v3', 'Standard_NC6', 'Standard_NC6s_v2',
     'Standard_NC6s_v3', 'Standard_ND12s', 'Standard_ND24rs', 'Standard_ND24s',
     'Standard_ND6s', 'Standard_NV12', 'Standard_NV24', 'Standard_NV6'
    :type vm_size: str or
     ~azure.mgmt.containerservice.models.ContainerServiceVMSizeTypes
    :param os_disk_size_gb: OS Disk Size in GB to be used to specify the disk
     size for every machine in this master/agent pool. If you specify 0, it
     will apply the default osDisk size according to the vmSize specified.
    :type os_disk_size_gb: int
    :param dns_prefix: DNS prefix to be used to create the FQDN for the agent
     pool.
    :type dns_prefix: str
    :ivar fqdn: FDQN for the agent pool.
    :vartype fqdn: str
    :param ports: Ports number array used to expose on this agent pool. The
     default opened ports are different based on your choice of orchestrator.
    :type ports: list[int]
    :param storage_profile: Storage profile specifies what kind of storage
     used. Choose from StorageAccount and ManagedDisks. Leave it empty, we will
     choose for you based on the orchestrator choice. Possible values include:
     'StorageAccount', 'ManagedDisks'
    :type storage_profile: str or
     ~azure.mgmt.containerservice.models.ContainerServiceStorageProfileTypes
    :param vnet_subnet_id: VNet SubnetID specifies the vnet's subnet
     identifier.
    :type vnet_subnet_id: str
    :param max_pods: Maximum number of pods that can run on a node.
    :type max_pods: int
    :param os_type: OsType to be used to specify os type. Choose from Linux
     and Windows. Default to Linux. Possible values include: 'Linux',
     'Windows'. Default value: "Linux" .
    :type os_type: str or ~azure.mgmt.containerservice.models.OSType
    """

    _validation = {
        'name': {'required': True},
        'count': {'maximum': 100, 'minimum': 1},
        'vm_size': {'required': True},
        'fqdn': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'count': {'key': 'count', 'type': 'int'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'os_disk_size_gb': {'key': 'osDiskSizeGB', 'type': 'int'},
        'dns_prefix': {'key': 'dnsPrefix', 'type': 'str'},
        'fqdn': {'key': 'fqdn', 'type': 'str'},
        'ports': {'key': 'ports', 'type': '[int]'},
        'storage_profile': {'key': 'storageProfile', 'type': 'str'},
        'vnet_subnet_id': {'key': 'vnetSubnetID', 'type': 'str'},
        'max_pods': {'key': 'maxPods', 'type': 'int'},
        'os_type': {'key': 'osType', 'type': 'str'},
    }

    def __init__(self, *, name: str, vm_size, count: int=1, os_disk_size_gb: int=None, dns_prefix: str=None, ports=None, storage_profile=None, vnet_subnet_id: str=None, max_pods: int=None, os_type="Linux", **kwargs) -> None:
        super(ManagedClusterAgentPoolProfile, self).__init__(**kwargs)
        self.name = name
        self.count = count
        self.vm_size = vm_size
        self.os_disk_size_gb = os_disk_size_gb
        self.dns_prefix = dns_prefix
        self.fqdn = None
        self.ports = ports
        self.storage_profile = storage_profile
        self.vnet_subnet_id = vnet_subnet_id
        self.max_pods = max_pods
        self.os_type = os_type
