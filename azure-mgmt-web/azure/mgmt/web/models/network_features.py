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

from .proxy_only_resource import ProxyOnlyResource


class NetworkFeatures(ProxyOnlyResource):
    """Full view of network features for an app (presently VNET integration and
    Hybrid Connections).

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar virtual_network_name: The Virtual Network name.
    :vartype virtual_network_name: str
    :ivar virtual_network_connection: The Virtual Network summary view.
    :vartype virtual_network_connection: ~azure.mgmt.web.models.VnetInfo
    :ivar hybrid_connections: The Hybrid Connections summary view.
    :vartype hybrid_connections:
     list[~azure.mgmt.web.models.RelayServiceConnectionEntity]
    :ivar hybrid_connections_v2: The Hybrid Connection V2 (Service Bus) view.
    :vartype hybrid_connections_v2:
     list[~azure.mgmt.web.models.HybridConnection]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'virtual_network_name': {'readonly': True},
        'virtual_network_connection': {'readonly': True},
        'hybrid_connections': {'readonly': True},
        'hybrid_connections_v2': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'virtual_network_name': {'key': 'properties.virtualNetworkName', 'type': 'str'},
        'virtual_network_connection': {'key': 'properties.virtualNetworkConnection', 'type': 'VnetInfo'},
        'hybrid_connections': {'key': 'properties.hybridConnections', 'type': '[RelayServiceConnectionEntity]'},
        'hybrid_connections_v2': {'key': 'properties.hybridConnectionsV2', 'type': '[HybridConnection]'},
    }

    def __init__(self, kind=None):
        super(NetworkFeatures, self).__init__(kind=kind)
        self.virtual_network_name = None
        self.virtual_network_connection = None
        self.hybrid_connections = None
        self.hybrid_connections_v2 = None
