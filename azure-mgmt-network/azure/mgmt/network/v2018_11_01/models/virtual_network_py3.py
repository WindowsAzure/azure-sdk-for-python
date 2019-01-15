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


class VirtualNetwork(Resource):
    """Virtual Network resource.

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
    :param address_space: The AddressSpace that contains an array of IP
     address ranges that can be used by subnets.
    :type address_space: ~azure.mgmt.network.v2018_11_01.models.AddressSpace
    :param dhcp_options: The dhcpOptions that contains an array of DNS servers
     available to VMs deployed in the virtual network.
    :type dhcp_options: ~azure.mgmt.network.v2018_11_01.models.DhcpOptions
    :param subnets: A list of subnets in a Virtual Network.
    :type subnets: list[~azure.mgmt.network.v2018_11_01.models.Subnet]
    :param virtual_network_peerings: A list of peerings in a Virtual Network.
    :type virtual_network_peerings:
     list[~azure.mgmt.network.v2018_11_01.models.VirtualNetworkPeering]
    :param resource_guid: The resourceGuid property of the Virtual Network
     resource.
    :type resource_guid: str
    :param provisioning_state: The provisioning state of the PublicIP
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param enable_ddos_protection: Indicates if DDoS protection is enabled for
     all the protected resources in the virtual network. It requires a DDoS
     protection plan associated with the resource. Default value: False .
    :type enable_ddos_protection: bool
    :param enable_vm_protection: Indicates if VM protection is enabled for all
     the subnets in the virtual network. Default value: False .
    :type enable_vm_protection: bool
    :param ddos_protection_plan: The DDoS protection plan associated with the
     virtual network.
    :type ddos_protection_plan:
     ~azure.mgmt.network.v2018_11_01.models.SubResource
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated.
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
        'virtual_network_peerings': {'key': 'properties.virtualNetworkPeerings', 'type': '[VirtualNetworkPeering]'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'enable_ddos_protection': {'key': 'properties.enableDdosProtection', 'type': 'bool'},
        'enable_vm_protection': {'key': 'properties.enableVmProtection', 'type': 'bool'},
        'ddos_protection_plan': {'key': 'properties.ddosProtectionPlan', 'type': 'SubResource'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, location: str=None, tags=None, address_space=None, dhcp_options=None, subnets=None, virtual_network_peerings=None, resource_guid: str=None, provisioning_state: str=None, enable_ddos_protection: bool=False, enable_vm_protection: bool=False, ddos_protection_plan=None, etag: str=None, **kwargs) -> None:
        super(VirtualNetwork, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.address_space = address_space
        self.dhcp_options = dhcp_options
        self.subnets = subnets
        self.virtual_network_peerings = virtual_network_peerings
        self.resource_guid = resource_guid
        self.provisioning_state = provisioning_state
        self.enable_ddos_protection = enable_ddos_protection
        self.enable_vm_protection = enable_vm_protection
        self.ddos_protection_plan = ddos_protection_plan
        self.etag = etag
