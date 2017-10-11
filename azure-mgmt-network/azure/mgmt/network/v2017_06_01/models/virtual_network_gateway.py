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


class VirtualNetworkGateway(Resource):
    """A common class for general resource information.

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
    :param ip_configurations: IP configurations for virtual network gateway.
    :type ip_configurations:
     list[~azure.mgmt.network.v2017_06_01.models.VirtualNetworkGatewayIPConfiguration]
    :param gateway_type: The type of this virtual network gateway. Possible
     values are: 'Vpn' and 'ExpressRoute'. Possible values include: 'Vpn',
     'ExpressRoute'
    :type gateway_type: str or
     ~azure.mgmt.network.v2017_06_01.models.VirtualNetworkGatewayType
    :param vpn_type: The type of this virtual network gateway. Possible values
     are: 'PolicyBased' and 'RouteBased'. Possible values include:
     'PolicyBased', 'RouteBased'
    :type vpn_type: str or ~azure.mgmt.network.v2017_06_01.models.VpnType
    :param enable_bgp: Whether BGP is enabled for this virtual network gateway
     or not.
    :type enable_bgp: bool
    :param active_active: ActiveActive flag
    :type active_active: bool
    :param gateway_default_site: The reference of the LocalNetworkGateway
     resource which represents local network site having default routes. Assign
     Null value in case of removing existing default site setting.
    :type gateway_default_site:
     ~azure.mgmt.network.v2017_06_01.models.SubResource
    :param sku: The reference of the VirtualNetworkGatewaySku resource which
     represents the SKU selected for Virtual network gateway.
    :type sku: ~azure.mgmt.network.v2017_06_01.models.VirtualNetworkGatewaySku
    :param vpn_client_configuration: The reference of the
     VpnClientConfiguration resource which represents the P2S VpnClient
     configurations.
    :type vpn_client_configuration:
     ~azure.mgmt.network.v2017_06_01.models.VpnClientConfiguration
    :param bgp_settings: Virtual network gateway's BGP speaker settings.
    :type bgp_settings: ~azure.mgmt.network.v2017_06_01.models.BgpSettings
    :param resource_guid: The resource GUID property of the
     VirtualNetworkGateway resource.
    :type resource_guid: str
    :ivar provisioning_state: The provisioning state of the
     VirtualNetworkGateway resource. Possible values are: 'Updating',
     'Deleting', and 'Failed'.
    :vartype provisioning_state: str
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :type etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'ip_configurations': {'key': 'properties.ipConfigurations', 'type': '[VirtualNetworkGatewayIPConfiguration]'},
        'gateway_type': {'key': 'properties.gatewayType', 'type': 'str'},
        'vpn_type': {'key': 'properties.vpnType', 'type': 'str'},
        'enable_bgp': {'key': 'properties.enableBgp', 'type': 'bool'},
        'active_active': {'key': 'properties.activeActive', 'type': 'bool'},
        'gateway_default_site': {'key': 'properties.gatewayDefaultSite', 'type': 'SubResource'},
        'sku': {'key': 'properties.sku', 'type': 'VirtualNetworkGatewaySku'},
        'vpn_client_configuration': {'key': 'properties.vpnClientConfiguration', 'type': 'VpnClientConfiguration'},
        'bgp_settings': {'key': 'properties.bgpSettings', 'type': 'BgpSettings'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, location=None, tags=None, ip_configurations=None, gateway_type=None, vpn_type=None, enable_bgp=None, active_active=None, gateway_default_site=None, sku=None, vpn_client_configuration=None, bgp_settings=None, resource_guid=None, etag=None):
        super(VirtualNetworkGateway, self).__init__(id=id, location=location, tags=tags)
        self.ip_configurations = ip_configurations
        self.gateway_type = gateway_type
        self.vpn_type = vpn_type
        self.enable_bgp = enable_bgp
        self.active_active = active_active
        self.gateway_default_site = gateway_default_site
        self.sku = sku
        self.vpn_client_configuration = vpn_client_configuration
        self.bgp_settings = bgp_settings
        self.resource_guid = resource_guid
        self.provisioning_state = None
        self.etag = etag
