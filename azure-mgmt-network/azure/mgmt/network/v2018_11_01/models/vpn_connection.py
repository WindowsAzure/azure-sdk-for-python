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


class VpnConnection(SubResource):
    """VpnConnection Resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param remote_vpn_site: Id of the connected vpn site.
    :type remote_vpn_site: ~azure.mgmt.network.v2018_11_01.models.SubResource
    :param routing_weight: routing weight for vpn connection.
    :type routing_weight: int
    :param connection_status: The connection status. Possible values include:
     'Unknown', 'Connecting', 'Connected', 'NotConnected'
    :type connection_status: str or
     ~azure.mgmt.network.v2018_11_01.models.VpnConnectionStatus
    :param vpn_connection_protocol_type: Connection protocol used for this
     connection. Possible values include: 'IKEv2', 'IKEv1'
    :type vpn_connection_protocol_type: str or
     ~azure.mgmt.network.v2018_11_01.models.VirtualNetworkGatewayConnectionProtocol
    :ivar ingress_bytes_transferred: Ingress bytes transferred.
    :vartype ingress_bytes_transferred: long
    :ivar egress_bytes_transferred: Egress bytes transferred.
    :vartype egress_bytes_transferred: long
    :param connection_bandwidth: Expected bandwidth in MBPS.
    :type connection_bandwidth: int
    :param shared_key: SharedKey for the vpn connection.
    :type shared_key: str
    :param enable_bgp: EnableBgp flag
    :type enable_bgp: bool
    :param ipsec_policies: The IPSec Policies to be considered by this
     connection.
    :type ipsec_policies:
     list[~azure.mgmt.network.v2018_11_01.models.IpsecPolicy]
    :param enable_rate_limiting: EnableBgp flag
    :type enable_rate_limiting: bool
    :param enable_internet_security: Enable internet security
    :type enable_internet_security: bool
    :param provisioning_state: The provisioning state of the resource.
     Possible values include: 'Succeeded', 'Updating', 'Deleting', 'Failed'
    :type provisioning_state: str or
     ~azure.mgmt.network.v2018_11_01.models.ProvisioningState
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :ivar etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :vartype etag: str
    """

    _validation = {
        'ingress_bytes_transferred': {'readonly': True},
        'egress_bytes_transferred': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'remote_vpn_site': {'key': 'properties.remoteVpnSite', 'type': 'SubResource'},
        'routing_weight': {'key': 'properties.routingWeight', 'type': 'int'},
        'connection_status': {'key': 'properties.connectionStatus', 'type': 'str'},
        'vpn_connection_protocol_type': {'key': 'properties.vpnConnectionProtocolType', 'type': 'str'},
        'ingress_bytes_transferred': {'key': 'properties.ingressBytesTransferred', 'type': 'long'},
        'egress_bytes_transferred': {'key': 'properties.egressBytesTransferred', 'type': 'long'},
        'connection_bandwidth': {'key': 'properties.connectionBandwidth', 'type': 'int'},
        'shared_key': {'key': 'properties.sharedKey', 'type': 'str'},
        'enable_bgp': {'key': 'properties.enableBgp', 'type': 'bool'},
        'ipsec_policies': {'key': 'properties.ipsecPolicies', 'type': '[IpsecPolicy]'},
        'enable_rate_limiting': {'key': 'properties.enableRateLimiting', 'type': 'bool'},
        'enable_internet_security': {'key': 'properties.enableInternetSecurity', 'type': 'bool'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(VpnConnection, self).__init__(**kwargs)
        self.remote_vpn_site = kwargs.get('remote_vpn_site', None)
        self.routing_weight = kwargs.get('routing_weight', None)
        self.connection_status = kwargs.get('connection_status', None)
        self.vpn_connection_protocol_type = kwargs.get('vpn_connection_protocol_type', None)
        self.ingress_bytes_transferred = None
        self.egress_bytes_transferred = None
        self.connection_bandwidth = kwargs.get('connection_bandwidth', None)
        self.shared_key = kwargs.get('shared_key', None)
        self.enable_bgp = kwargs.get('enable_bgp', None)
        self.ipsec_policies = kwargs.get('ipsec_policies', None)
        self.enable_rate_limiting = kwargs.get('enable_rate_limiting', None)
        self.enable_internet_security = kwargs.get('enable_internet_security', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.name = kwargs.get('name', None)
        self.etag = None
