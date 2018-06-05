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

from .fabric_event_py3 import FabricEvent


class ReplicaEvent(FabricEvent):
    """Represents the base for all Replica Events.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: StatefulReplicaHealthReportCreatedEvent,
    StatefulReplicaHealthReportExpiredEvent,
    StatelessReplicaHealthReportCreatedEvent,
    StatelessReplicaHealthReportExpiredEvent,
    ChaosRemoveReplicaFaultScheduledEvent,
    ChaosRemoveReplicaFaultCompletedEvent,
    ChaosRestartReplicaFaultScheduledEvent

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
    :param replica_id: Required. Id of a stateful service replica. ReplicaId
     is used by Service Fabric to uniquely identify a replica of a partition.
     It is unique within a partition and does not change for the lifetime of
     the replica. If a replica gets dropped and another replica gets created on
     the same node for the same partition, it will get a different value for
     the id. Sometimes the id of a stateless service instance is also referred
     as a replica id.
    :type replica_id: long
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'partition_id': {'required': True},
        'replica_id': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'partition_id': {'key': 'PartitionId', 'type': 'str'},
        'replica_id': {'key': 'ReplicaId', 'type': 'long'},
    }

    _subtype_map = {
        'kind': {'StatefulReplicaHealthReportCreated': 'StatefulReplicaHealthReportCreatedEvent', 'StatefulReplicaHealthReportExpired': 'StatefulReplicaHealthReportExpiredEvent', 'StatelessReplicaHealthReportCreated': 'StatelessReplicaHealthReportCreatedEvent', 'StatelessReplicaHealthReportExpired': 'StatelessReplicaHealthReportExpiredEvent', 'ChaosRemoveReplicaFaultScheduled': 'ChaosRemoveReplicaFaultScheduledEvent', 'ChaosRemoveReplicaFaultCompleted': 'ChaosRemoveReplicaFaultCompletedEvent', 'ChaosRestartReplicaFaultScheduled': 'ChaosRestartReplicaFaultScheduledEvent'}
    }

    def __init__(self, *, event_instance_id: str, time_stamp, partition_id: str, replica_id: int, has_correlated_events: bool=None, **kwargs) -> None:
        super(ReplicaEvent, self).__init__(event_instance_id=event_instance_id, time_stamp=time_stamp, has_correlated_events=has_correlated_events, **kwargs)
        self.partition_id = partition_id
        self.replica_id = replica_id
        self.kind = 'ReplicaEvent'
