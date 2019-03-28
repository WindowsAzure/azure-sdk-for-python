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


class BgpPeerStatus(Model):
    """BGP peer status details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar local_address: The virtual network gateway's local address
    :vartype local_address: str
    :ivar neighbor: The remote BGP peer
    :vartype neighbor: str
    :ivar asn: The autonomous system number of the remote BGP peer
    :vartype asn: int
    :ivar state: The BGP peer state. Possible values include: 'Unknown',
     'Stopped', 'Idle', 'Connecting', 'Connected'
    :vartype state: str or ~azure.mgmt.network.v2018_12_01.models.BgpPeerState
    :ivar connected_duration: For how long the peering has been up
    :vartype connected_duration: str
    :ivar routes_received: The number of routes learned from this peer
    :vartype routes_received: long
    :ivar messages_sent: The number of BGP messages sent
    :vartype messages_sent: long
    :ivar messages_received: The number of BGP messages received
    :vartype messages_received: long
    """

    _validation = {
        'local_address': {'readonly': True},
        'neighbor': {'readonly': True},
        'asn': {'readonly': True},
        'state': {'readonly': True},
        'connected_duration': {'readonly': True},
        'routes_received': {'readonly': True},
        'messages_sent': {'readonly': True},
        'messages_received': {'readonly': True},
    }

    _attribute_map = {
        'local_address': {'key': 'localAddress', 'type': 'str'},
        'neighbor': {'key': 'neighbor', 'type': 'str'},
        'asn': {'key': 'asn', 'type': 'int'},
        'state': {'key': 'state', 'type': 'str'},
        'connected_duration': {'key': 'connectedDuration', 'type': 'str'},
        'routes_received': {'key': 'routesReceived', 'type': 'long'},
        'messages_sent': {'key': 'messagesSent', 'type': 'long'},
        'messages_received': {'key': 'messagesReceived', 'type': 'long'},
    }

    def __init__(self, **kwargs) -> None:
        super(BgpPeerStatus, self).__init__(**kwargs)
        self.local_address = None
        self.neighbor = None
        self.asn = None
        self.state = None
        self.connected_duration = None
        self.routes_received = None
        self.messages_sent = None
        self.messages_received = None
