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


class Subnet(SubResource):
    """Subnet in a VirtualNework resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource Id
    :type id: str
    :param address_prefix: Gets or sets Address prefix for the subnet.
    :type address_prefix: str
    :param network_security_group: Gets or sets the reference of the
     NetworkSecurityGroup resource
    :type network_security_group: :class:`NetworkSecurityGroup
     <azure.mgmt.network.models.NetworkSecurityGroup>`
    :param route_table: Gets or sets the reference of the RouteTable resource
    :type route_table: :class:`RouteTable
     <azure.mgmt.network.models.RouteTable>`
    :ivar ip_configurations: Gets array of references to the network
     interface IP configurations using subnet
    :vartype ip_configurations: list of :class:`IPConfiguration
     <azure.mgmt.network.models.IPConfiguration>`
    :param provisioning_state: Gets provisioning state of the resource
    :type provisioning_state: str
    :param name: Gets or sets the name of the resource that is unique within
     a resource group. This name can be used to access the resource
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated
    :type etag: str
    """ 

    _validation = {
        'ip_configurations': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'address_prefix': {'key': 'properties.addressPrefix', 'type': 'str'},
        'network_security_group': {'key': 'properties.networkSecurityGroup', 'type': 'NetworkSecurityGroup'},
        'route_table': {'key': 'properties.routeTable', 'type': 'RouteTable'},
        'ip_configurations': {'key': 'properties.ipConfigurations', 'type': '[IPConfiguration]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, address_prefix=None, network_security_group=None, route_table=None, provisioning_state=None, name=None, etag=None):
        super(Subnet, self).__init__(id=id)
        self.address_prefix = address_prefix
        self.network_security_group = network_security_group
        self.route_table = route_table
        self.ip_configurations = None
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
