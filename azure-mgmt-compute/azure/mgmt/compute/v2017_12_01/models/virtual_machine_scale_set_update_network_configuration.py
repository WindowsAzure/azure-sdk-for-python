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


class VirtualMachineScaleSetUpdateNetworkConfiguration(SubResource):
    """Describes a virtual machine scale set network profile's network
    configurations.

    :param id: Resource Id
    :type id: str
    :param name: The network configuration name.
    :type name: str
    :param primary: Whether this is a primary NIC on a virtual machine.
    :type primary: bool
    :param enable_accelerated_networking: Specifies whether the network
     interface is accelerated networking-enabled.
    :type enable_accelerated_networking: bool
    :param network_security_group: The network security group.
    :type network_security_group:
     ~azure.mgmt.compute.v2017_12_01.models.SubResource
    :param dns_settings: The dns settings to be applied on the network
     interfaces.
    :type dns_settings:
     ~azure.mgmt.compute.v2017_12_01.models.VirtualMachineScaleSetNetworkConfigurationDnsSettings
    :param ip_configurations: The virtual machine scale set IP Configuration.
    :type ip_configurations:
     list[~azure.mgmt.compute.v2017_12_01.models.VirtualMachineScaleSetUpdateIPConfiguration]
    :param enable_ip_forwarding: Whether IP forwarding enabled on this NIC.
    :type enable_ip_forwarding: bool
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'primary': {'key': 'properties.primary', 'type': 'bool'},
        'enable_accelerated_networking': {'key': 'properties.enableAcceleratedNetworking', 'type': 'bool'},
        'network_security_group': {'key': 'properties.networkSecurityGroup', 'type': 'SubResource'},
        'dns_settings': {'key': 'properties.dnsSettings', 'type': 'VirtualMachineScaleSetNetworkConfigurationDnsSettings'},
        'ip_configurations': {'key': 'properties.ipConfigurations', 'type': '[VirtualMachineScaleSetUpdateIPConfiguration]'},
        'enable_ip_forwarding': {'key': 'properties.enableIPForwarding', 'type': 'bool'},
    }

    def __init__(self, id=None, name=None, primary=None, enable_accelerated_networking=None, network_security_group=None, dns_settings=None, ip_configurations=None, enable_ip_forwarding=None):
        super(VirtualMachineScaleSetUpdateNetworkConfiguration, self).__init__(id=id)
        self.name = name
        self.primary = primary
        self.enable_accelerated_networking = enable_accelerated_networking
        self.network_security_group = network_security_group
        self.dns_settings = dns_settings
        self.ip_configurations = ip_configurations
        self.enable_ip_forwarding = enable_ip_forwarding
