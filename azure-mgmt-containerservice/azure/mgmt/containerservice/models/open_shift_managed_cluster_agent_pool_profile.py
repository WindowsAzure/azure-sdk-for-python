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
    """OpenShiftManagedClusterAgentPoolProfile represents configuration of
    OpenShift cluster VMs.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Unique name of the pool profile in the context of
     the subscription and resource group.
    :type name: str
    :param count: Required. Number of agents (VMs) to host docker containers.
     Allowed values must be in the range of 1 to 100 (inclusive). The default
     value is 1. . Default value: 1 .
    :type count: int
    :param vm_size: Required. Size of agent VMs. Possible values include:
     'Standard_D2s_v3', 'Standard_D4s_v3'
    :type vm_size: str or
     ~azure.mgmt.containerservice.models.OpenShiftContainerServiceVMSize
    :param vnet_subnet_id: VNet SubnetID specifies the vnet's subnet
     identifier.
    :type vnet_subnet_id: str
    :param os_type: OsType to be used to specify os type. Choose from Linux
     and Windows. Default to Linux. Possible values include: 'Linux',
     'Windows'. Default value: "Linux" .
    :type os_type: str or ~azure.mgmt.containerservice.models.OSType
    :param role: Define the role of the AgentPoolProfile. Possible values
     include: 'compute', 'infra'
    :type role: str or
     ~azure.mgmt.containerservice.models.OpenShiftAgentPoolProfileRole
    """

    _validation = {
        'name': {'required': True},
        'count': {'required': True, 'maximum': 100, 'minimum': 1},
        'vm_size': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'count': {'key': 'count', 'type': 'int'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'vnet_subnet_id': {'key': 'vnetSubnetID', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'role': {'key': 'role', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterAgentPoolProfile, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.count = kwargs.get('count', 1)
        self.vm_size = kwargs.get('vm_size', None)
        self.vnet_subnet_id = kwargs.get('vnet_subnet_id', None)
        self.os_type = kwargs.get('os_type', "Linux")
        self.role = kwargs.get('role', None)
