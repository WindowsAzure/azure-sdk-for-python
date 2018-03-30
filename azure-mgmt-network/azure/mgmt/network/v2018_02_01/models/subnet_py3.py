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

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param address_prefix: The address prefix for the subnet.
    :type address_prefix: str
    :param network_security_group: The reference of the NetworkSecurityGroup
     resource.
    :type network_security_group:
     ~azure.mgmt.network.v2018_02_01.models.NetworkSecurityGroup
    :param route_table: The reference of the RouteTable resource.
    :type route_table: ~azure.mgmt.network.v2018_02_01.models.RouteTable
    :param service_endpoints: An array of service endpoints.
    :type service_endpoints:
     list[~azure.mgmt.network.v2018_02_01.models.ServiceEndpointPropertiesFormat]
    :ivar ip_configurations: Gets an array of references to the network
     interface IP configurations using subnet.
    :vartype ip_configurations:
     list[~azure.mgmt.network.v2018_02_01.models.IPConfiguration]
    :param resource_navigation_links: Gets an array of references to the
     external resources using subnet.
    :type resource_navigation_links:
     list[~azure.mgmt.network.v2018_02_01.models.ResourceNavigationLink]
    :param provisioning_state: The provisioning state of the resource.
    :type provisioning_state: str
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
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
        'service_endpoints': {'key': 'properties.serviceEndpoints', 'type': '[ServiceEndpointPropertiesFormat]'},
        'ip_configurations': {'key': 'properties.ipConfigurations', 'type': '[IPConfiguration]'},
        'resource_navigation_links': {'key': 'properties.resourceNavigationLinks', 'type': '[ResourceNavigationLink]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, address_prefix: str=None, network_security_group=None, route_table=None, service_endpoints=None, resource_navigation_links=None, provisioning_state: str=None, name: str=None, etag: str=None, **kwargs) -> None:
        super(Subnet, self).__init__(id=id, **kwargs)
        self.address_prefix = address_prefix
        self.network_security_group = network_security_group
        self.route_table = route_table
        self.service_endpoints = service_endpoints
        self.ip_configurations = None
        self.resource_navigation_links = resource_navigation_links
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
