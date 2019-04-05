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


class PartitionNewHealthReportEvent(PartitionEvent):
    """Partition Health Report Created event.

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
    :param partition_id: Required. An internal ID used by Service Fabric to
     uniquely identify a partition. This is a randomly generated GUID when the
     service was created. The partition ID is unique and does not change for
     the lifetime of the service. If the same service was deleted and recreated
     the IDs of its partitions would be different.
    :type partition_id: str
    :param source_id: Required. Id of report source.
    :type source_id: str
    :param property: Required. Describes the property.
    :type property: str
    :param health_state: Required. Describes the property health state.
    :type health_state: str
    :param time_to_live_ms: Required. Time to live in milli-seconds.
    :type time_to_live_ms: long
    :param sequence_number: Required. Sequence number of report.
    :type sequence_number: long
    :param description: Required. Description of report.
    :type description: str
    :param remove_when_expired: Required. Indicates the removal when it
     expires.
    :type remove_when_expired: bool
    :param source_utc_timestamp: Required. Source time.
    :type source_utc_timestamp: datetime
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'partition_id': {'required': True},
        'source_id': {'required': True},
        'property': {'required': True},
        'health_state': {'required': True},
        'time_to_live_ms': {'required': True},
        'sequence_number': {'required': True},
        'description': {'required': True},
        'remove_when_expired': {'required': True},
        'source_utc_timestamp': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'category': {'key': 'Category', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'partition_id': {'key': 'PartitionId', 'type': 'str'},
        'source_id': {'key': 'SourceId', 'type': 'str'},
        'property': {'key': 'Property', 'type': 'str'},
        'health_state': {'key': 'HealthState', 'type': 'str'},
        'time_to_live_ms': {'key': 'TimeToLiveMs', 'type': 'long'},
        'sequence_number': {'key': 'SequenceNumber', 'type': 'long'},
        'description': {'key': 'Description', 'type': 'str'},
        'remove_when_expired': {'key': 'RemoveWhenExpired', 'type': 'bool'},
        'source_utc_timestamp': {'key': 'SourceUtcTimestamp', 'type': 'iso-8601'},
    }

    def __init__(self, *, event_instance_id: str, time_stamp, partition_id: str, source_id: str, property: str, health_state: str, time_to_live_ms: int, sequence_number: int, description: str, remove_when_expired: bool, source_utc_timestamp, category: str=None, has_correlated_events: bool=None, **kwargs) -> None:
        super(PartitionNewHealthReportEvent, self).__init__(event_instance_id=event_instance_id, category=category, time_stamp=time_stamp, has_correlated_events=has_correlated_events, partition_id=partition_id, **kwargs)
        self.source_id = source_id
        self.property = property
        self.health_state = health_state
        self.time_to_live_ms = time_to_live_ms
        self.sequence_number = sequence_number
        self.description = description
        self.remove_when_expired = remove_when_expired
        self.source_utc_timestamp = source_utc_timestamp
        self.kind = 'PartitionNewHealthReport'
