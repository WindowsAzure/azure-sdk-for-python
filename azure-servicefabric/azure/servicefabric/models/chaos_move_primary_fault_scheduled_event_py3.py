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

from .partition_event_py3 import PartitionEvent


class ChaosMovePrimaryFaultScheduledEvent(PartitionEvent):
    """Chaos Move Primary Fault Scheduled event.

    All required parameters must be populated in order to send to Azure.

    :param event_instance_id: Required. The identifier for the FabricEvent
     instance.
    :type event_instance_id: str
    :param time_stamp: Required. The time event was logged.
    :type time_stamp: datetime
    :param has_correlated_events: Shows there is existing related events
     available.
    :type has_correlated_events: bool
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param partition_id: Required. An internal ID used by Service Fabric to
     uniquely identify a partition. This is a randomly generated GUID when the
     service was created. The partition ID is unique and does not change for
     the lifetime of the service. If the same service was deleted and recreated
     the IDs of its partitions would be different.
    :type partition_id: str
    :param fault_group_id: Required. Id of fault group.
    :type fault_group_id: str
    :param fault_id: Required. Id of fault.
    :type fault_id: str
    :param service_name: Required. Service name.
    :type service_name: str
    :param node_to: Required. The name of a Service Fabric node.
    :type node_to: str
    :param forced_move: Required. Indicates a forced move.
    :type forced_move: bool
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'partition_id': {'required': True},
        'fault_group_id': {'required': True},
        'fault_id': {'required': True},
        'service_name': {'required': True},
        'node_to': {'required': True},
        'forced_move': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'partition_id': {'key': 'PartitionId', 'type': 'str'},
        'fault_group_id': {'key': 'FaultGroupId', 'type': 'str'},
        'fault_id': {'key': 'FaultId', 'type': 'str'},
        'service_name': {'key': 'ServiceName', 'type': 'str'},
        'node_to': {'key': 'NodeTo', 'type': 'str'},
        'forced_move': {'key': 'ForcedMove', 'type': 'bool'},
    }

    def __init__(self, *, event_instance_id: str, time_stamp, partition_id: str, fault_group_id: str, fault_id: str, service_name: str, node_to: str, forced_move: bool, has_correlated_events: bool=None, **kwargs) -> None:
        super(ChaosMovePrimaryFaultScheduledEvent, self).__init__(event_instance_id=event_instance_id, time_stamp=time_stamp, has_correlated_events=has_correlated_events, partition_id=partition_id, **kwargs)
        self.fault_group_id = fault_group_id
        self.fault_id = fault_id
        self.service_name = service_name
        self.node_to = node_to
        self.forced_move = forced_move
        self.kind = 'ChaosMovePrimaryFaultScheduled'
