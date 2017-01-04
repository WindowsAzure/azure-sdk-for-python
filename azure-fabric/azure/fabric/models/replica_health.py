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


class ReplicaHealth(Model):
    """The health of the replica.

    :param service_kind: Possible values include: 'Invalid', 'Stateless',
     'Stateful'
    :type service_kind: str or :class:`enum <azure.fabric.models.enum>`
    :param partition_id:
    :type partition_id: str
    :param replica_id:
    :type replica_id: str
    :param health_events:
    :type health_events: list of :class:`HealthEvent
     <azure.fabric.models.HealthEvent>`
    :param aggregated_health_state: Possible values include: 'Invalid', 'Ok',
     'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or :class:`enum
     <azure.fabric.models.enum>`
    """

    _attribute_map = {
        'service_kind': {'key': 'ServiceKind', 'type': 'str'},
        'partition_id': {'key': 'PartitionId', 'type': 'str'},
        'replica_id': {'key': 'ReplicaId', 'type': 'str'},
        'health_events': {'key': 'HealthEvents', 'type': '[HealthEvent]'},
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
    }

    def __init__(self, service_kind=None, partition_id=None, replica_id=None, health_events=None, aggregated_health_state=None):
        self.service_kind = service_kind
        self.partition_id = partition_id
        self.replica_id = replica_id
        self.health_events = health_events
        self.aggregated_health_state = aggregated_health_state
