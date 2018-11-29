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

from .node_event import NodeEvent


class NodeAbortedEvent(NodeEvent):
    """Node Aborted event.

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
    :param node_instance: Required. Id of Node instance.
    :type node_instance: long
    :param node_id: Required. Id of Node.
    :type node_id: str
    :param upgrade_domain: Required. Upgrade domain of Node.
    :type upgrade_domain: str
    :param fault_domain: Required. Fault domain of Node.
    :type fault_domain: str
    :param ip_address_or_fqdn: Required. IP address or FQDN.
    :type ip_address_or_fqdn: str
    :param hostname: Required. Name of Host.
    :type hostname: str
    :param is_seed_node: Required. Indicates if it is seed node.
    :type is_seed_node: bool
    :param node_version: Required. Version of Node.
    :type node_version: str
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'node_name': {'required': True},
        'node_instance': {'required': True},
        'node_id': {'required': True},
        'upgrade_domain': {'required': True},
        'fault_domain': {'required': True},
        'ip_address_or_fqdn': {'required': True},
        'hostname': {'required': True},
        'is_seed_node': {'required': True},
        'node_version': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'category': {'key': 'Category', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'node_instance': {'key': 'NodeInstance', 'type': 'long'},
        'node_id': {'key': 'NodeId', 'type': 'str'},
        'upgrade_domain': {'key': 'UpgradeDomain', 'type': 'str'},
        'fault_domain': {'key': 'FaultDomain', 'type': 'str'},
        'ip_address_or_fqdn': {'key': 'IpAddressOrFQDN', 'type': 'str'},
        'hostname': {'key': 'Hostname', 'type': 'str'},
        'is_seed_node': {'key': 'IsSeedNode', 'type': 'bool'},
        'node_version': {'key': 'NodeVersion', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(NodeAbortedEvent, self).__init__(**kwargs)
        self.node_instance = kwargs.get('node_instance', None)
        self.node_id = kwargs.get('node_id', None)
        self.upgrade_domain = kwargs.get('upgrade_domain', None)
        self.fault_domain = kwargs.get('fault_domain', None)
        self.ip_address_or_fqdn = kwargs.get('ip_address_or_fqdn', None)
        self.hostname = kwargs.get('hostname', None)
        self.is_seed_node = kwargs.get('is_seed_node', None)
        self.node_version = kwargs.get('node_version', None)
        self.kind = 'NodeAborted'
