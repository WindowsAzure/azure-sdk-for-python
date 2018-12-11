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

from .service_partition_info_py3 import ServicePartitionInfo


class StatefulServicePartitionInfo(ServicePartitionInfo):
    """Information about a partition of a stateful Service Fabric service..

    All required parameters must be populated in order to send to Azure.

    :param health_state: The health state of a Service Fabric entity such as
     Cluster, Node, Application, Service, Partition, Replica etc. Possible
     values include: 'Invalid', 'Ok', 'Warning', 'Error', 'Unknown'
    :type health_state: str or ~azure.servicefabric.models.HealthState
    :param partition_status: The status of the service fabric service
     partition. Possible values include: 'Invalid', 'Ready', 'NotReady',
     'InQuorumLoss', 'Reconfiguring', 'Deleting'
    :type partition_status: str or
     ~azure.servicefabric.models.ServicePartitionStatus
    :param partition_information: Information about the partition identity,
     partitioning scheme and keys supported by it.
    :type partition_information:
     ~azure.servicefabric.models.PartitionInformation
    :param service_kind: Required. Constant filled by server.
    :type service_kind: str
    :param target_replica_set_size: The target replica set size as a number.
    :type target_replica_set_size: long
    :param min_replica_set_size: The minimum replica set size as a number.
    :type min_replica_set_size: long
    :param last_quorum_loss_duration: The duration for which this partition
     was in quorum loss. If the partition is currently in quorum loss, it
     returns the duration since it has been in that state. This field is using
     ISO8601 format for specifying the duration.
    :type last_quorum_loss_duration: timedelta
    :param primary_epoch: An Epoch is a configuration number for the partition
     as a whole. When the configuration of the replica set changes, for example
     when the Primary replica changes, the operations that are replicated from
     the new Primary replica are said to be a new Epoch from the ones which
     were sent by the old Primary replica.
    :type primary_epoch: ~azure.servicefabric.models.Epoch
    """

    _validation = {
        'service_kind': {'required': True},
    }

    _attribute_map = {
        'health_state': {'key': 'HealthState', 'type': 'str'},
        'partition_status': {'key': 'PartitionStatus', 'type': 'str'},
        'partition_information': {'key': 'PartitionInformation', 'type': 'PartitionInformation'},
        'service_kind': {'key': 'ServiceKind', 'type': 'str'},
        'target_replica_set_size': {'key': 'TargetReplicaSetSize', 'type': 'long'},
        'min_replica_set_size': {'key': 'MinReplicaSetSize', 'type': 'long'},
        'last_quorum_loss_duration': {'key': 'LastQuorumLossDuration', 'type': 'duration'},
        'primary_epoch': {'key': 'PrimaryEpoch', 'type': 'Epoch'},
    }

    def __init__(self, *, health_state=None, partition_status=None, partition_information=None, target_replica_set_size: int=None, min_replica_set_size: int=None, last_quorum_loss_duration=None, primary_epoch=None, **kwargs) -> None:
        super(StatefulServicePartitionInfo, self).__init__(health_state=health_state, partition_status=partition_status, partition_information=partition_information, **kwargs)
        self.target_replica_set_size = target_replica_set_size
        self.min_replica_set_size = min_replica_set_size
        self.last_quorum_loss_duration = last_quorum_loss_duration
        self.primary_epoch = primary_epoch
        self.service_kind = 'Stateful'
