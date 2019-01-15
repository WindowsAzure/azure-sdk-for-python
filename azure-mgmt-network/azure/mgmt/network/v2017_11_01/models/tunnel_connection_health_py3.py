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

from msrest.serialization import Model


class TunnelConnectionHealth(Model):
    """VirtualNetworkGatewayConnection properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar tunnel: Tunnel name.
    :vartype tunnel: str
    :ivar connection_status: Virtual network Gateway connection status.
     Possible values include: 'Unknown', 'Connecting', 'Connected',
     'NotConnected'
    :vartype connection_status: str or
     ~azure.mgmt.network.v2017_11_01.models.VirtualNetworkGatewayConnectionStatus
    :ivar ingress_bytes_transferred: The Ingress Bytes Transferred in this
     connection
    :vartype ingress_bytes_transferred: long
    :ivar egress_bytes_transferred: The Egress Bytes Transferred in this
     connection
    :vartype egress_bytes_transferred: long
    :ivar last_connection_established_utc_time: The time at which connection
     was established in Utc format.
    :vartype last_connection_established_utc_time: str
    """

    _validation = {
        'tunnel': {'readonly': True},
        'connection_status': {'readonly': True},
        'ingress_bytes_transferred': {'readonly': True},
        'egress_bytes_transferred': {'readonly': True},
        'last_connection_established_utc_time': {'readonly': True},
    }

    _attribute_map = {
        'tunnel': {'key': 'tunnel', 'type': 'str'},
        'connection_status': {'key': 'connectionStatus', 'type': 'str'},
        'ingress_bytes_transferred': {'key': 'ingressBytesTransferred', 'type': 'long'},
        'egress_bytes_transferred': {'key': 'egressBytesTransferred', 'type': 'long'},
        'last_connection_established_utc_time': {'key': 'lastConnectionEstablishedUtcTime', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(TunnelConnectionHealth, self).__init__(**kwargs)
        self.tunnel = None
        self.connection_status = None
        self.ingress_bytes_transferred = None
        self.egress_bytes_transferred = None
        self.last_connection_established_utc_time = None
