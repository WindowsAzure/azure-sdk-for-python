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

from .health_evaluation import HealthEvaluation


class ReplicaHealthEvaluation(HealthEvaluation):
    """The evaluation of the replica health.

    :param description:
    :type description: str
    :param aggregated_health_state: Possible values include: 'Invalid', 'Ok',
     'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or :class:`enum
     <azure.fabric.models.enum>`
    :param kind: Polymorphic Discriminator
    :type kind: str
    :param partition_id:
    :type partition_id: str
    :param replica_or_instance_id:
    :type replica_or_instance_id: str
    :param unhealthy_evaluations:
    :type unhealthy_evaluations: list of :class:`UnhealthyEvaluation
     <azure.fabric.models.UnhealthyEvaluation>`
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'description': {'key': 'Description', 'type': 'str'},
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'partition_id': {'key': 'PartitionId', 'type': 'str'},
        'replica_or_instance_id': {'key': 'ReplicaOrInstanceId', 'type': 'str'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[UnhealthyEvaluation]'},
    }

    def __init__(self, description=None, aggregated_health_state=None, partition_id=None, replica_or_instance_id=None, unhealthy_evaluations=None):
        super(ReplicaHealthEvaluation, self).__init__(description=description, aggregated_health_state=aggregated_health_state)
        self.partition_id = partition_id
        self.replica_or_instance_id = replica_or_instance_id
        self.unhealthy_evaluations = unhealthy_evaluations
        self.kind = 'Replica'
