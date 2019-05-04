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


class NetworkAdapter(Model):
    """Represents the networkAdapter on a device.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar adapter_id: Instance ID of network adapter.
    :vartype adapter_id: str
    :ivar adapter_position: Hardware position of network adapter.
    :vartype adapter_position:
     ~azure.mgmt.edgegateway.models.NetworkAdapterPosition
    :ivar index: Logical index of the adapter.
    :vartype index: int
    :ivar node_id: Node ID of the network adapter.
    :vartype node_id: str
    :ivar network_adapter_name: Network adapter name.
    :vartype network_adapter_name: str
    :ivar label: Hardware label for the adapter.
    :vartype label: str
    :ivar mac_address: MAC address.
    :vartype mac_address: str
    :ivar link_speed: Link speed.
    :vartype link_speed: long
    :ivar status: Value indicating whether this adapter is valid. Possible
     values include: 'Inactive', 'Active'
    :vartype status: str or
     ~azure.mgmt.edgegateway.models.NetworkAdapterStatus
    :param rdma_status: Value indicating whether this adapter is RDMA capable.
     Possible values include: 'Incapable', 'Capable'
    :type rdma_status: str or
     ~azure.mgmt.edgegateway.models.NetworkAdapterRDMAStatus
    :param dhcp_status: Value indicating whether this adapter has DHCP
     enabled. Possible values include: 'Disabled', 'Enabled'
    :type dhcp_status: str or
     ~azure.mgmt.edgegateway.models.NetworkAdapterDHCPStatus
    :ivar ipv4_configuration: The IPv4 configuration of the network adapter.
    :vartype ipv4_configuration: ~azure.mgmt.edgegateway.models.Ipv4Config
    :ivar ipv6_configuration: The IPv6 configuration of the network adapter.
    :vartype ipv6_configuration: ~azure.mgmt.edgegateway.models.Ipv6Config
    :ivar ipv6_link_local_address: The IPv6 local address.
    :vartype ipv6_link_local_address: str
    :ivar dns_servers: The list of DNS Servers of the device.
    :vartype dns_servers: list[str]
    """

    _validation = {
        'adapter_id': {'readonly': True},
        'adapter_position': {'readonly': True},
        'index': {'readonly': True},
        'node_id': {'readonly': True},
        'network_adapter_name': {'readonly': True},
        'label': {'readonly': True},
        'mac_address': {'readonly': True},
        'link_speed': {'readonly': True},
        'status': {'readonly': True},
        'ipv4_configuration': {'readonly': True},
        'ipv6_configuration': {'readonly': True},
        'ipv6_link_local_address': {'readonly': True},
        'dns_servers': {'readonly': True},
    }

    _attribute_map = {
        'adapter_id': {'key': 'adapterId', 'type': 'str'},
        'adapter_position': {'key': 'adapterPosition', 'type': 'NetworkAdapterPosition'},
        'index': {'key': 'index', 'type': 'int'},
        'node_id': {'key': 'nodeId', 'type': 'str'},
        'network_adapter_name': {'key': 'networkAdapterName', 'type': 'str'},
        'label': {'key': 'label', 'type': 'str'},
        'mac_address': {'key': 'macAddress', 'type': 'str'},
        'link_speed': {'key': 'linkSpeed', 'type': 'long'},
        'status': {'key': 'status', 'type': 'str'},
        'rdma_status': {'key': 'rdmaStatus', 'type': 'str'},
        'dhcp_status': {'key': 'dhcpStatus', 'type': 'str'},
        'ipv4_configuration': {'key': 'ipv4Configuration', 'type': 'Ipv4Config'},
        'ipv6_configuration': {'key': 'ipv6Configuration', 'type': 'Ipv6Config'},
        'ipv6_link_local_address': {'key': 'ipv6LinkLocalAddress', 'type': 'str'},
        'dns_servers': {'key': 'dnsServers', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(NetworkAdapter, self).__init__(**kwargs)
        self.adapter_id = None
        self.adapter_position = None
        self.index = None
        self.node_id = None
        self.network_adapter_name = None
        self.label = None
        self.mac_address = None
        self.link_speed = None
        self.status = None
        self.rdma_status = kwargs.get('rdma_status', None)
        self.dhcp_status = kwargs.get('dhcp_status', None)
        self.ipv4_configuration = None
        self.ipv6_configuration = None
        self.ipv6_link_local_address = None
        self.dns_servers = None
