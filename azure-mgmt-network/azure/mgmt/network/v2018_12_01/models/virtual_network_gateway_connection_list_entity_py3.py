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


class VirtualNetworkGatewayConnectionListEntity(Resource):
    """A common class for general resource information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

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
    :param authorization_key: The authorizationKey.
    :type authorization_key: str
    :param virtual_network_gateway1: Required. The reference to virtual
     network gateway resource.
    :type virtual_network_gateway1:
     ~azure.mgmt.network.v2018_12_01.models.VirtualNetworkConnectionGatewayReference
    :param virtual_network_gateway2: The reference to virtual network gateway
     resource.
    :type virtual_network_gateway2:
     ~azure.mgmt.network.v2018_12_01.models.VirtualNetworkConnectionGatewayReference
    :param local_network_gateway2: The reference to local network gateway
     resource.
    :type local_network_gateway2:
     ~azure.mgmt.network.v2018_12_01.models.VirtualNetworkConnectionGatewayReference
    :param connection_type: Required. Gateway connection type. Possible values
     are: 'Ipsec','Vnet2Vnet','ExpressRoute', and 'VPNClient. Possible values
     include: 'IPsec', 'Vnet2Vnet', 'ExpressRoute', 'VPNClient'
    :type connection_type: str or
     ~azure.mgmt.network.v2018_12_01.models.VirtualNetworkGatewayConnectionType
    :param connection_protocol: Connection protocol used for this connection.
     Possible values include: 'IKEv2', 'IKEv1'
    :type connection_protocol: str or
     ~azure.mgmt.network.v2018_12_01.models.VirtualNetworkGatewayConnectionProtocol
    :param routing_weight: The routing weight.
    :type routing_weight: int
    :param shared_key: The IPSec shared key.
    :type shared_key: str
    :ivar connection_status: Virtual network Gateway connection status.
     Possible values are 'Unknown', 'Connecting', 'Connected' and
     'NotConnected'. Possible values include: 'Unknown', 'Connecting',
     'Connected', 'NotConnected'
    :vartype connection_status: str or
     ~azure.mgmt.network.v2018_12_01.models.VirtualNetworkGatewayConnectionStatus
    :ivar tunnel_connection_status: Collection of all tunnels' connection
     health status.
    :vartype tunnel_connection_status:
     list[~azure.mgmt.network.v2018_12_01.models.TunnelConnectionHealth]
    :ivar egress_bytes_transferred: The egress bytes transferred in this
     connection.
    :vartype egress_bytes_transferred: long
    :ivar ingress_bytes_transferred: The ingress bytes transferred in this
     connection.
    :vartype ingress_bytes_transferred: long
    :param peer: The reference to peerings resource.
    :type peer: ~azure.mgmt.network.v2018_12_01.models.SubResource
    :param enable_bgp: EnableBgp flag
    :type enable_bgp: bool
    :param use_policy_based_traffic_selectors: Enable policy-based traffic
     selectors.
    :type use_policy_based_traffic_selectors: bool
    :param ipsec_policies: The IPSec Policies to be considered by this
     connection.
    :type ipsec_policies:
     list[~azure.mgmt.network.v2018_12_01.models.IpsecPolicy]
    :param resource_guid: The resource GUID property of the
     VirtualNetworkGatewayConnection resource.
    :type resource_guid: str
    :ivar provisioning_state: The provisioning state of the
     VirtualNetworkGatewayConnection resource. Possible values are: 'Updating',
     'Deleting', and 'Failed'.
    :vartype provisioning_state: str
    :param express_route_gateway_bypass: Bypass ExpressRoute Gateway for data
     forwarding
    :type express_route_gateway_bypass: bool
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :type etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'virtual_network_gateway1': {'required': True},
        'connection_type': {'required': True},
        'connection_status': {'readonly': True},
        'tunnel_connection_status': {'readonly': True},
        'egress_bytes_transferred': {'readonly': True},
        'ingress_bytes_transferred': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'authorization_key': {'key': 'properties.authorizationKey', 'type': 'str'},
        'virtual_network_gateway1': {'key': 'properties.virtualNetworkGateway1', 'type': 'VirtualNetworkConnectionGatewayReference'},
        'virtual_network_gateway2': {'key': 'properties.virtualNetworkGateway2', 'type': 'VirtualNetworkConnectionGatewayReference'},
        'local_network_gateway2': {'key': 'properties.localNetworkGateway2', 'type': 'VirtualNetworkConnectionGatewayReference'},
        'connection_type': {'key': 'properties.connectionType', 'type': 'str'},
        'connection_protocol': {'key': 'properties.connectionProtocol', 'type': 'str'},
        'routing_weight': {'key': 'properties.routingWeight', 'type': 'int'},
        'shared_key': {'key': 'properties.sharedKey', 'type': 'str'},
        'connection_status': {'key': 'properties.connectionStatus', 'type': 'str'},
        'tunnel_connection_status': {'key': 'properties.tunnelConnectionStatus', 'type': '[TunnelConnectionHealth]'},
        'egress_bytes_transferred': {'key': 'properties.egressBytesTransferred', 'type': 'long'},
        'ingress_bytes_transferred': {'key': 'properties.ingressBytesTransferred', 'type': 'long'},
        'peer': {'key': 'properties.peer', 'type': 'SubResource'},
        'enable_bgp': {'key': 'properties.enableBgp', 'type': 'bool'},
        'use_policy_based_traffic_selectors': {'key': 'properties.usePolicyBasedTrafficSelectors', 'type': 'bool'},
        'ipsec_policies': {'key': 'properties.ipsecPolicies', 'type': '[IpsecPolicy]'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'express_route_gateway_bypass': {'key': 'properties.expressRouteGatewayBypass', 'type': 'bool'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, virtual_network_gateway1, connection_type, id: str=None, location: str=None, tags=None, authorization_key: str=None, virtual_network_gateway2=None, local_network_gateway2=None, connection_protocol=None, routing_weight: int=None, shared_key: str=None, peer=None, enable_bgp: bool=None, use_policy_based_traffic_selectors: bool=None, ipsec_policies=None, resource_guid: str=None, express_route_gateway_bypass: bool=None, etag: str=None, **kwargs) -> None:
        super(VirtualNetworkGatewayConnectionListEntity, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.authorization_key = authorization_key
        self.virtual_network_gateway1 = virtual_network_gateway1
        self.virtual_network_gateway2 = virtual_network_gateway2
        self.local_network_gateway2 = local_network_gateway2
        self.connection_type = connection_type
        self.connection_protocol = connection_protocol
        self.routing_weight = routing_weight
        self.shared_key = shared_key
        self.connection_status = None
        self.tunnel_connection_status = None
        self.egress_bytes_transferred = None
        self.ingress_bytes_transferred = None
        self.peer = peer
        self.enable_bgp = enable_bgp
        self.use_policy_based_traffic_selectors = use_policy_based_traffic_selectors
        self.ipsec_policies = ipsec_policies
        self.resource_guid = resource_guid
        self.provisioning_state = None
        self.express_route_gateway_bypass = express_route_gateway_bypass
        self.etag = etag
