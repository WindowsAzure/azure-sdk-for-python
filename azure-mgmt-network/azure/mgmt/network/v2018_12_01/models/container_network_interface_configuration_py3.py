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

from .sub_resource_py3 import SubResource


class ContainerNetworkInterfaceConfiguration(SubResource):
    """Container network interface configruation child resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param ip_configurations: A list of ip configurations of the container
     network interface configuration.
    :type ip_configurations:
     list[~azure.mgmt.network.v2018_12_01.models.IPConfigurationProfile]
    :param container_network_interfaces: A list of container network
     interfaces created from this container network interface configuration.
    :type container_network_interfaces:
     list[~azure.mgmt.network.v2018_12_01.models.SubResource]
    :ivar provisioning_state: The provisioning state of the resource.
    :vartype provisioning_state: str
    :param name: The name of the resource. This name can be used to access the
     resource.
    :type name: str
    :ivar type: Sub Resource type.
    :vartype type: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'ip_configurations': {'key': 'properties.ipConfigurations', 'type': '[IPConfigurationProfile]'},
        'container_network_interfaces': {'key': 'properties.containerNetworkInterfaces', 'type': '[SubResource]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, ip_configurations=None, container_network_interfaces=None, name: str=None, etag: str=None, **kwargs) -> None:
        super(ContainerNetworkInterfaceConfiguration, self).__init__(id=id, **kwargs)
        self.ip_configurations = ip_configurations
        self.container_network_interfaces = container_network_interfaces
        self.provisioning_state = None
        self.name = name
        self.type = None
        self.etag = etag
