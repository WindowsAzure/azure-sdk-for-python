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

from .entity_health_state_chunk_py3 import EntityHealthStateChunk


class PartitionHealthStateChunk(EntityHealthStateChunk):
    """Represents the health state chunk of a partition, which contains the
    partition ID, its aggregated health state and any replicas that respect the
    filters in the cluster health chunk query description.

    :param health_state: The health state of a Service Fabric entity such as
     Cluster, Node, Application, Service, Partition, Replica etc. Possible
     values include: 'Invalid', 'Ok', 'Warning', 'Error', 'Unknown'
    :type health_state: str or ~azure.servicefabric.models.HealthState
    :param partition_id: The Id of the partition.
    :type partition_id: str
    :param replica_health_state_chunks: The list of replica health state
     chunks belonging to the partition that respect the filters in the cluster
     health chunk query description.
    :type replica_health_state_chunks:
     ~azure.servicefabric.models.ReplicaHealthStateChunkList
    """

    _attribute_map = {
        'health_state': {'key': 'HealthState', 'type': 'str'},
        'partition_id': {'key': 'PartitionId', 'type': 'str'},
        'replica_health_state_chunks': {'key': 'ReplicaHealthStateChunks', 'type': 'ReplicaHealthStateChunkList'},
    }

    def __init__(self, *, health_state=None, partition_id: str=None, replica_health_state_chunks=None, **kwargs) -> None:
        super(PartitionHealthStateChunk, self).__init__(health_state=health_state, **kwargs)
        self.partition_id = partition_id
        self.replica_health_state_chunks = replica_health_state_chunks
