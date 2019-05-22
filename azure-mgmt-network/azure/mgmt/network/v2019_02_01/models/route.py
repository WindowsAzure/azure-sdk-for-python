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


class Route(SubResource):
    """Route resource.

    All required parameters must be populated in order to send to Azure.

    :param id: Resource ID.
    :type id: str
    :param address_prefix: The destination CIDR to which the route applies.
    :type address_prefix: str
    :param next_hop_type: Required. The type of Azure hop the packet should be
     sent to. Possible values include: 'VirtualNetworkGateway', 'VnetLocal',
     'Internet', 'VirtualAppliance', 'None'
    :type next_hop_type: str or
     ~azure.mgmt.network.v2019_02_01.models.RouteNextHopType
    :param next_hop_ip_address: The IP address packets should be forwarded to.
     Next hop values are only allowed in routes where the next hop type is
     VirtualAppliance.
    :type next_hop_ip_address: str
    :param provisioning_state: The provisioning state of the resource.
     Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _validation = {
        'next_hop_type': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'address_prefix': {'key': 'properties.addressPrefix', 'type': 'str'},
        'next_hop_type': {'key': 'properties.nextHopType', 'type': 'str'},
        'next_hop_ip_address': {'key': 'properties.nextHopIpAddress', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Route, self).__init__(**kwargs)
        self.address_prefix = kwargs.get('address_prefix', None)
        self.next_hop_type = kwargs.get('next_hop_type', None)
        self.next_hop_ip_address = kwargs.get('next_hop_ip_address', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.name = kwargs.get('name', None)
        self.etag = kwargs.get('etag', None)
