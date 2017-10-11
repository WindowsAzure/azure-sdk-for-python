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
    """Subnet in a virtual network resource.

    :param id: Resource Identifier.
    :type id: str
    :param address_prefix: The address prefix for the subnet.
    :type address_prefix: str
    :param network_security_group: The reference of the NetworkSecurityGroup
     resource.
    :type network_security_group:
     ~azure.mgmt.network.v2015_06_15.models.NetworkSecurityGroup
    :param route_table: The reference of the RouteTable resource.
    :type route_table: ~azure.mgmt.network.v2015_06_15.models.RouteTable
    :param ip_configurations: Gets an array of references to the network
     interface IP configurations using subnet.
    :type ip_configurations:
     list[~azure.mgmt.network.v2015_06_15.models.IPConfiguration]
    :param provisioning_state: The provisioning state of the resource.
    :type provisioning_state: str
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

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

    def __init__(self, id=None, address_prefix=None, network_security_group=None, route_table=None, ip_configurations=None, provisioning_state=None, name=None, etag=None):
        super(Subnet, self).__init__(id=id)
        self.address_prefix = address_prefix
        self.network_security_group = network_security_group
        self.route_table = route_table
        self.ip_configurations = ip_configurations
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
