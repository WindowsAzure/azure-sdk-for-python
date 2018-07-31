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


class VpnConnection(Resource):
    """VpnConnection Resource.

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
    :param remote_vpn_site: Id of the connected vpn site.
    :type remote_vpn_site: ~azure.mgmt.network.v2018_04_01.models.SubResource
    :param routing_weight: routing weight for vpn connection.
    :type routing_weight: int
    :param connection_status: The connection status. Possible values include:
     'Unknown', 'Connecting', 'Connected', 'NotConnected'
    :type connection_status: str or
     ~azure.mgmt.network.v2018_04_01.models.VpnConnectionStatus
    :ivar ingress_bytes_transferred: Ingress bytes transferred.
    :vartype ingress_bytes_transferred: long
    :ivar egress_bytes_transferred: Egress bytes transferred.
    :vartype egress_bytes_transferred: long
    :ivar connection_bandwidth: Expected bandwidth in MBPS.
    :vartype connection_bandwidth: int
    :param shared_key: SharedKey for the vpn connection.
    :type shared_key: str
    :param enable_bgp: EnableBgp flag
    :type enable_bgp: bool
    :param ipsec_policies: The IPSec Policies to be considered by this
     connection.
    :type ipsec_policies:
     list[~azure.mgmt.network.v2018_04_01.models.IpsecPolicy]
    :param provisioning_state: The provisioning state of the resource.
     Possible values include: 'Succeeded', 'Updating', 'Deleting', 'Failed'
    :type provisioning_state: str or
     ~azure.mgmt.network.v2018_04_01.models.ProvisioningState
    :ivar etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :vartype etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'ingress_bytes_transferred': {'readonly': True},
        'egress_bytes_transferred': {'readonly': True},
        'connection_bandwidth': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'remote_vpn_site': {'key': 'properties.remoteVpnSite', 'type': 'SubResource'},
        'routing_weight': {'key': 'properties.routingWeight', 'type': 'int'},
        'connection_status': {'key': 'properties.connectionStatus', 'type': 'str'},
        'ingress_bytes_transferred': {'key': 'properties.ingressBytesTransferred', 'type': 'long'},
        'egress_bytes_transferred': {'key': 'properties.egressBytesTransferred', 'type': 'long'},
        'connection_bandwidth': {'key': 'properties.connectionBandwidth', 'type': 'int'},
        'shared_key': {'key': 'properties.sharedKey', 'type': 'str'},
        'enable_bgp': {'key': 'properties.enableBgp', 'type': 'bool'},
        'ipsec_policies': {'key': 'properties.ipsecPolicies', 'type': '[IpsecPolicy]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(VpnConnection, self).__init__(**kwargs)
        self.remote_vpn_site = kwargs.get('remote_vpn_site', None)
        self.routing_weight = kwargs.get('routing_weight', None)
        self.connection_status = kwargs.get('connection_status', None)
        self.ingress_bytes_transferred = None
        self.egress_bytes_transferred = None
        self.connection_bandwidth = None
        self.shared_key = kwargs.get('shared_key', None)
        self.enable_bgp = kwargs.get('enable_bgp', None)
        self.ipsec_policies = kwargs.get('ipsec_policies', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.etag = None
