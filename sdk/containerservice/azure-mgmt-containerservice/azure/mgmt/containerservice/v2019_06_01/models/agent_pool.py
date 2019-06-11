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

from .sub_resource import SubResource


class AgentPool(SubResource):
    """Agent Pool.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param count: Required. Number of agents (VMs) to host docker containers.
     Allowed values must be in the range of 1 to 100 (inclusive). The default
     value is 1. . Default value: 1 .
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
     ~azure.mgmt.containerservice.v2019_06_01.models.ContainerServiceVMSizeTypes
    :param os_disk_size_gb: OS Disk Size in GB to be used to specify the disk
     size for every machine in this master/agent pool. If you specify 0, it
     will apply the default osDisk size according to the vmSize specified.
    :type os_disk_size_gb: int
    :param vnet_subnet_id: VNet SubnetID specifies the VNet's subnet
     identifier.
    :type vnet_subnet_id: str
    :param max_pods: Maximum number of pods that can run on a node.
    :type max_pods: int
    :param os_type: OsType to be used to specify os type. Choose from Linux
     and Windows. Default to Linux. Possible values include: 'Linux',
     'Windows'. Default value: "Linux" .
    :type os_type: str or
     ~azure.mgmt.containerservice.v2019_06_01.models.OSType
    :param max_count: Maximum number of nodes for auto-scaling
    :type max_count: int
    :param min_count: Minimum number of nodes for auto-scaling
    :type min_count: int
    :param enable_auto_scaling: Whether to enable auto-scaler
    :type enable_auto_scaling: bool
    :param agent_pool_type: AgentPoolType represents types of an agent pool.
     Possible values include: 'VirtualMachineScaleSets', 'AvailabilitySet'
    :type agent_pool_type: str or
     ~azure.mgmt.containerservice.v2019_06_01.models.AgentPoolType
    :param orchestrator_version: Version of orchestrator specified when
     creating the managed cluster.
    :type orchestrator_version: str
    :ivar provisioning_state: The current deployment or provisioning state,
     which only appears in the response.
    :vartype provisioning_state: str
    :param availability_zones: (PREVIEW) Availability zones for nodes. Must
     use VirtualMachineScaleSets AgentPoolType.
    :type availability_zones: list[str]
    :param enable_node_public_ip: Enable public IP for nodes
    :type enable_node_public_ip: bool
    :param scale_set_priority: ScaleSetPriority to be used to specify virtual
     machine scale set priority. Default to regular. Possible values include:
     'Low', 'Regular'. Default value: "Regular" .
    :type scale_set_priority: str or
     ~azure.mgmt.containerservice.v2019_06_01.models.ScaleSetPriority
    :param scale_set_eviction_policy: ScaleSetEvictionPolicy to be used to
     specify eviction policy for low priority virtual machine scale set.
     Default to Delete. Possible values include: 'Delete', 'Deallocate'.
     Default value: "Delete" .
    :type scale_set_eviction_policy: str or
     ~azure.mgmt.containerservice.v2019_06_01.models.ScaleSetEvictionPolicy
    :param node_taints: Taints to add when registering nodes.
    :type node_taints: list[str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'count': {'required': True, 'maximum': 100, 'minimum': 1},
        'vm_size': {'required': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'count': {'key': 'properties.count', 'type': 'int'},
        'vm_size': {'key': 'properties.vmSize', 'type': 'str'},
        'os_disk_size_gb': {'key': 'properties.osDiskSizeGB', 'type': 'int'},
        'vnet_subnet_id': {'key': 'properties.vnetSubnetID', 'type': 'str'},
        'max_pods': {'key': 'properties.maxPods', 'type': 'int'},
        'os_type': {'key': 'properties.osType', 'type': 'str'},
        'max_count': {'key': 'properties.maxCount', 'type': 'int'},
        'min_count': {'key': 'properties.minCount', 'type': 'int'},
        'enable_auto_scaling': {'key': 'properties.enableAutoScaling', 'type': 'bool'},
        'agent_pool_type': {'key': 'properties.type', 'type': 'str'},
        'orchestrator_version': {'key': 'properties.orchestratorVersion', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'availability_zones': {'key': 'properties.availabilityZones', 'type': '[str]'},
        'enable_node_public_ip': {'key': 'properties.enableNodePublicIP', 'type': 'bool'},
        'scale_set_priority': {'key': 'properties.scaleSetPriority', 'type': 'str'},
        'scale_set_eviction_policy': {'key': 'properties.scaleSetEvictionPolicy', 'type': 'str'},
        'node_taints': {'key': 'properties.nodeTaints', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(AgentPool, self).__init__(**kwargs)
        self.count = kwargs.get('count', 1)
        self.vm_size = kwargs.get('vm_size', None)
        self.os_disk_size_gb = kwargs.get('os_disk_size_gb', None)
        self.vnet_subnet_id = kwargs.get('vnet_subnet_id', None)
        self.max_pods = kwargs.get('max_pods', None)
        self.os_type = kwargs.get('os_type', "Linux")
        self.max_count = kwargs.get('max_count', None)
        self.min_count = kwargs.get('min_count', None)
        self.enable_auto_scaling = kwargs.get('enable_auto_scaling', None)
        self.agent_pool_type = kwargs.get('agent_pool_type', None)
        self.orchestrator_version = kwargs.get('orchestrator_version', None)
        self.provisioning_state = None
        self.availability_zones = kwargs.get('availability_zones', None)
        self.enable_node_public_ip = kwargs.get('enable_node_public_ip', None)
        self.scale_set_priority = kwargs.get('scale_set_priority', "Regular")
        self.scale_set_eviction_policy = kwargs.get('scale_set_eviction_policy', "Delete")
        self.node_taints = kwargs.get('node_taints', None)
