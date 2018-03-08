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


class VirtualMachineScaleSetNetworkConfiguration(SubResource):
    """Describes a virtual machine scale set network profile's network
    configurations.

    All required parameters must be populated in order to send to Azure.

    :param id: Resource Id
    :type id: str
    :param name: Required. The network configuration name.
    :type name: str
    :param primary: Whether this is a primary NIC on a virtual machine.
    :type primary: bool
    :param ip_configurations: Required. The virtual machine scale set IP
     Configuration.
    :type ip_configurations:
     list[~azure.mgmt.compute.v2016_04_30_preview.models.VirtualMachineScaleSetIPConfiguration]
    """

    _validation = {
        'name': {'required': True},
        'ip_configurations': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'primary': {'key': 'properties.primary', 'type': 'bool'},
        'ip_configurations': {'key': 'properties.ipConfigurations', 'type': '[VirtualMachineScaleSetIPConfiguration]'},
    }

    def __init__(self, *, name: str, ip_configurations, id: str=None, primary: bool=None, **kwargs) -> None:
        super(VirtualMachineScaleSetNetworkConfiguration, self).__init__(id=id, **kwargs)
        self.name = name
        self.primary = primary
        self.ip_configurations = ip_configurations
