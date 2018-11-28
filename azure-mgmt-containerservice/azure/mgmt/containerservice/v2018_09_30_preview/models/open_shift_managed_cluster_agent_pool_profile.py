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


class OpenShiftManagedClusterAgentPoolProfile(Model):
    """Defines the configuration of the OpenShift cluster VMs.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Unique name of the pool profile in the context of
     the subscription and resource group.
    :type name: str
    :param count: Required. Number of agents (VMs) to host docker containers.
     Allowed values must be in the range of 1 to 5 (inclusive). The default
     value is 2.
    :type count: int
    :param vm_size: Required. Size of agent VMs. Possible values include:
     'Standard_D2s_v3', 'Standard_D4s_v3', 'Standard_D8s_v3',
     'Standard_D16s_v3', 'Standard_D32s_v3', 'Standard_D64s_v3',
     'Standard_DS4_v2', 'Standard_DS5_v2', 'Standard_F8s_v2',
     'Standard_F16s_v2', 'Standard_F32s_v2', 'Standard_F64s_v2',
     'Standard_F72s_v2', 'Standard_F8s', 'Standard_F16s', 'Standard_E4s_v3',
     'Standard_E8s_v3', 'Standard_E16s_v3', 'Standard_E20s_v3',
     'Standard_E32s_v3', 'Standard_E64s_v3', 'Standard_GS2', 'Standard_GS3',
     'Standard_GS4', 'Standard_GS5', 'Standard_DS12_v2', 'Standard_DS13_v2',
     'Standard_DS14_v2', 'Standard_DS15_v2', 'Standard_L4s', 'Standard_L8s',
     'Standard_L16s', 'Standard_L32s'
    :type vm_size: str or
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftContainerServiceVMSize
    :param subnet_cidr: Subnet CIDR for the peering. Default value:
     "10.0.0.0/24" .
    :type subnet_cidr: str
    :param os_type: OsType to be used to specify os type. Choose from Linux
     and Windows. Default to Linux. Possible values include: 'Linux',
     'Windows'. Default value: "Linux" .
    :type os_type: str or
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OSType
    :param role: Define the role of the AgentPoolProfile. Possible values
     include: 'compute', 'infra'
    :type role: str or
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftAgentPoolProfileRole
    """

    _validation = {
        'name': {'required': True},
        'count': {'required': True},
        'vm_size': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'count': {'key': 'count', 'type': 'int'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'subnet_cidr': {'key': 'subnetCidr', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'role': {'key': 'role', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterAgentPoolProfile, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.count = kwargs.get('count', None)
        self.vm_size = kwargs.get('vm_size', None)
        self.subnet_cidr = kwargs.get('subnet_cidr', "10.0.0.0/24")
        self.os_type = kwargs.get('os_type', "Linux")
        self.role = kwargs.get('role', None)
