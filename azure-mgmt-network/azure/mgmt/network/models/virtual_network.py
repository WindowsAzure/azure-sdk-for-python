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

from .resource import Resource


class VirtualNetwork(Resource):
    """Virtual Network resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource Id
    :type id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param address_space: Gets or sets AddressSpace that contains an array of
     IP address ranges that can be used by subnets
    :type address_space: :class:`AddressSpace
     <azure.mgmt.network.models.AddressSpace>`
    :param dhcp_options: Gets or sets DHCPOptions that contains an array of
     DNS servers available to VMs deployed in the virtual network
    :type dhcp_options: :class:`DhcpOptions
     <azure.mgmt.network.models.DhcpOptions>`
    :param subnets: Gets or sets list of subnets in a VirtualNetwork
    :type subnets: list of :class:`Subnet <azure.mgmt.network.models.Subnet>`
    :param virtual_network_peerings: Gets or sets list of peerings in a
     VirtualNetwork
    :type virtual_network_peerings: list of :class:`VirtualNetworkPeering
     <azure.mgmt.network.models.VirtualNetworkPeering>`
    :param resource_guid: Gets or sets resource guid property of the
     VirtualNetwork resource
    :type resource_guid: str
    :param provisioning_state: Gets provisioning state of the PublicIP
     resource Updating/Deleting/Failed
    :type provisioning_state: str
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated
    :type etag: str
    """ 

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'address_space': {'key': 'properties.addressSpace', 'type': 'AddressSpace'},
        'dhcp_options': {'key': 'properties.dhcpOptions', 'type': 'DhcpOptions'},
        'subnets': {'key': 'properties.subnets', 'type': '[Subnet]'},
        'virtual_network_peerings': {'key': 'properties.VirtualNetworkPeerings', 'type': '[VirtualNetworkPeering]'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, location=None, tags=None, address_space=None, dhcp_options=None, subnets=None, virtual_network_peerings=None, resource_guid=None, provisioning_state=None, etag=None):
        super(VirtualNetwork, self).__init__(id=id, location=location, tags=tags)
        self.address_space = address_space
        self.dhcp_options = dhcp_options
        self.subnets = subnets
        self.virtual_network_peerings = virtual_network_peerings
        self.resource_guid = resource_guid
        self.provisioning_state = provisioning_state
        self.etag = etag
