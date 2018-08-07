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

from .health_evaluation_py3 import HealthEvaluation


class ReplicaHealthEvaluation(HealthEvaluation):
    """Represents health evaluation for a replica, containing information about
    the data and the algorithm used by health store to evaluate health. The
    evaluation is returned only when the aggregated health state is either
    Error or Warning.

    All required parameters must be populated in order to send to Azure.

    :param aggregated_health_state: The health state of a Service Fabric
     entity such as Cluster, Node, Application, Service, Partition, Replica
     etc. Possible values include: 'Invalid', 'Ok', 'Warning', 'Error',
     'Unknown'
    :type aggregated_health_state: str or
     ~azure.servicefabric.models.HealthState
    :param description: Description of the health evaluation, which represents
     a summary of the evaluation process.
    :type description: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param partition_id: Id of the partition to which the replica belongs.
    :type partition_id: str
    :param replica_or_instance_id: Id of a stateful service replica or a
     stateless service instance. This ID is used in the queries that apply to
     both stateful and stateless services. It is used by Service Fabric to
     uniquely identify a replica of a partition of a stateful service or an
     instance of a stateless service partition. It is unique within a partition
     and does not change for the lifetime of the replica or the instance. If a
     stateful replica gets dropped and another replica gets created on the same
     node for the same partition, it will get a different value for the ID. If
     a stateless instance is failed over on the same or different node it will
     get a different value for the ID.
    :type replica_or_instance_id: str
    :param unhealthy_evaluations: List of unhealthy evaluations that led to
     the current aggregated health state of the replica. The types of the
     unhealthy evaluations can be EventHealthEvaluation.
    :type unhealthy_evaluations:
     list[~azure.servicefabric.models.HealthEvaluationWrapper]
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'description': {'key': 'Description', 'type': 'str'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'partition_id': {'key': 'PartitionId', 'type': 'str'},
        'replica_or_instance_id': {'key': 'ReplicaOrInstanceId', 'type': 'str'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[HealthEvaluationWrapper]'},
    }

    def __init__(self, *, aggregated_health_state=None, description: str=None, partition_id: str=None, replica_or_instance_id: str=None, unhealthy_evaluations=None, **kwargs) -> None:
        super(ReplicaHealthEvaluation, self).__init__(aggregated_health_state=aggregated_health_state, description=description, **kwargs)
        self.partition_id = partition_id
        self.replica_or_instance_id = replica_or_instance_id
        self.unhealthy_evaluations = unhealthy_evaluations
        self.kind = 'Replica'
