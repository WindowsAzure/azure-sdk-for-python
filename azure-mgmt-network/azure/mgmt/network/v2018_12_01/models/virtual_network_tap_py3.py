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

from .resource_py3 import Resource


class VirtualNetworkTap(Resource):
    """Virtual Network Tap resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :ivar network_interface_tap_configurations: Specifies the list of resource
     IDs for the network interface IP configuration that needs to be tapped.
    :vartype network_interface_tap_configurations:
     list[~azure.mgmt.network.v2018_12_01.models.NetworkInterfaceTapConfiguration]
    :ivar resource_guid: The resourceGuid property of the virtual network tap.
    :vartype resource_guid: str
    :ivar provisioning_state: The provisioning state of the virtual network
     tap. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :vartype provisioning_state: str
    :param destination_network_interface_ip_configuration: The reference to
     the private IP Address of the collector nic that will receive the tap
    :type destination_network_interface_ip_configuration:
     ~azure.mgmt.network.v2018_12_01.models.NetworkInterfaceIPConfiguration
    :param destination_load_balancer_front_end_ip_configuration: The reference
     to the private IP address on the internal Load Balancer that will receive
     the tap
    :type destination_load_balancer_front_end_ip_configuration:
     ~azure.mgmt.network.v2018_12_01.models.FrontendIPConfiguration
    :param destination_port: The VXLAN destination port that will receive the
     tapped traffic.
    :type destination_port: int
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :type etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'network_interface_tap_configurations': {'readonly': True},
        'resource_guid': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'network_interface_tap_configurations': {'key': 'properties.networkInterfaceTapConfigurations', 'type': '[NetworkInterfaceTapConfiguration]'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'destination_network_interface_ip_configuration': {'key': 'properties.destinationNetworkInterfaceIPConfiguration', 'type': 'NetworkInterfaceIPConfiguration'},
        'destination_load_balancer_front_end_ip_configuration': {'key': 'properties.destinationLoadBalancerFrontEndIPConfiguration', 'type': 'FrontendIPConfiguration'},
        'destination_port': {'key': 'properties.destinationPort', 'type': 'int'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, location: str=None, tags=None, destination_network_interface_ip_configuration=None, destination_load_balancer_front_end_ip_configuration=None, destination_port: int=None, etag: str=None, **kwargs) -> None:
        super(VirtualNetworkTap, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.network_interface_tap_configurations = None
        self.resource_guid = None
        self.provisioning_state = None
        self.destination_network_interface_ip_configuration = destination_network_interface_ip_configuration
        self.destination_load_balancer_front_end_ip_configuration = destination_load_balancer_front_end_ip_configuration
        self.destination_port = destination_port
        self.etag = etag
