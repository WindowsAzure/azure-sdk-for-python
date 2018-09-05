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


class ContainerNetworkInterfaceConfigurationPropertiesFormat(Model):
    """Container network interface configuration properties.

    :param ip_configurations: A list of ip configurations of the container
     network interface configuration.
    :type ip_configurations:
     list[~azure.mgmt.network.v2018_08_01.models.IPConfigurationProfile]
    :param container_network_interfaces: A list of container network
     interfaces created from this container network interface configuration.
    :type container_network_interfaces:
     list[~azure.mgmt.network.v2018_08_01.models.ContainerNetworkInterface]
    """

    _attribute_map = {
        'ip_configurations': {'key': 'ipConfigurations', 'type': '[IPConfigurationProfile]'},
        'container_network_interfaces': {'key': 'containerNetworkInterfaces', 'type': '[ContainerNetworkInterface]'},
    }

    def __init__(self, **kwargs):
        super(ContainerNetworkInterfaceConfigurationPropertiesFormat, self).__init__(**kwargs)
        self.ip_configurations = kwargs.get('ip_configurations', None)
        self.container_network_interfaces = kwargs.get('container_network_interfaces', None)
