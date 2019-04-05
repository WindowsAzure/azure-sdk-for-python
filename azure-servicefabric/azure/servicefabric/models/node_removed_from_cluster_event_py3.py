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

from .node_event_py3 import NodeEvent


class NodeRemovedFromClusterEvent(NodeEvent):
    """Node Removed event.

    All required parameters must be populated in order to send to Azure.

    :param event_instance_id: Required. The identifier for the FabricEvent
     instance.
    :type event_instance_id: str
    :param category: The category of event.
    :type category: str
    :param time_stamp: Required. The time event was logged.
    :type time_stamp: datetime
    :param has_correlated_events: Shows there is existing related events
     available.
    :type has_correlated_events: bool
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param node_name: Required. The name of a Service Fabric node.
    :type node_name: str
    :param node_id: Required. Id of Node.
    :type node_id: str
    :param node_instance: Required. Id of Node instance.
    :type node_instance: long
    :param node_type: Required. Type of Node.
    :type node_type: str
    :param fabric_version: Required. Fabric version.
    :type fabric_version: str
    :param ip_address_or_fqdn: Required. IP address or FQDN.
    :type ip_address_or_fqdn: str
    :param node_capacities: Required. Capacities.
    :type node_capacities: str
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'node_name': {'required': True},
        'node_id': {'required': True},
        'node_instance': {'required': True},
        'node_type': {'required': True},
        'fabric_version': {'required': True},
        'ip_address_or_fqdn': {'required': True},
        'node_capacities': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'category': {'key': 'Category', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'node_id': {'key': 'NodeId', 'type': 'str'},
        'node_instance': {'key': 'NodeInstance', 'type': 'long'},
        'node_type': {'key': 'NodeType', 'type': 'str'},
        'fabric_version': {'key': 'FabricVersion', 'type': 'str'},
        'ip_address_or_fqdn': {'key': 'IpAddressOrFQDN', 'type': 'str'},
        'node_capacities': {'key': 'NodeCapacities', 'type': 'str'},
    }

    def __init__(self, *, event_instance_id: str, time_stamp, node_name: str, node_id: str, node_instance: int, node_type: str, fabric_version: str, ip_address_or_fqdn: str, node_capacities: str, category: str=None, has_correlated_events: bool=None, **kwargs) -> None:
        super(NodeRemovedFromClusterEvent, self).__init__(event_instance_id=event_instance_id, category=category, time_stamp=time_stamp, has_correlated_events=has_correlated_events, node_name=node_name, **kwargs)
        self.node_id = node_id
        self.node_instance = node_instance
        self.node_type = node_type
        self.fabric_version = fabric_version
        self.ip_address_or_fqdn = ip_address_or_fqdn
        self.node_capacities = node_capacities
        self.kind = 'NodeRemovedFromCluster'
