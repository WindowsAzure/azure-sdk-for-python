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

from .deployed_service_replica_detail_info import DeployedServiceReplicaDetailInfo


class DeployedStatefulServiceReplicaDetailInfo(DeployedServiceReplicaDetailInfo):
    """Information about a stateful replica running in a code package. Please note
    DeployedServiceReplicaQueryResult will contain duplicate data like
    ServiceKind, ServiceName, PartitionId and replicaId.

    :param service_name:
    :type service_name: str
    :param partition_id:
    :type partition_id: str
    :param current_service_operation: Possible values include: 'Unknown',
     'None', 'Open', 'ChangeRole', 'Close', 'Abort'
    :type current_service_operation: str or ~azure.servicefabric.models.enum
    :param current_service_operation_start_time_utc: The start time of the
     current service operation in UTC format.
    :type current_service_operation_start_time_utc: datetime
    :param reported_load:
    :type reported_load:
     list[~azure.servicefabric.models.LoadMetricReportInfo]
    :param service_kind: Constant filled by server.
    :type service_kind: str
    :param replica_id:
    :type replica_id: str
    :param current_replicator_operation: Possible values include: 'Invalid',
     'None', 'Open', 'ChangeRole', 'UpdateEpoch', 'Close', 'Abort',
     'OnDataLoss', 'WaitForCatchup', 'Build'
    :type current_replicator_operation: str or
     ~azure.servicefabric.models.enum
    :param read_status: Possible values include: 'Invalid', 'Granted',
     'ReconfigurationPending', 'NotPrimary', 'NoWriteQuorum'
    :type read_status: str or ~azure.servicefabric.models.enum
    :param write_status: Possible values include: 'Invalid', 'Granted',
     'ReconfigurationPending', 'NotPrimary', 'NoWriteQuorum'
    :type write_status: str or ~azure.servicefabric.models.enum
    :param replicator_status:
    :type replicator_status: ~azure.servicefabric.models.ReplicatorStatus
    :param replica_status:
    :type replica_status:
     ~azure.servicefabric.models.KeyValueStoreReplicaStatus
    :param deployed_service_replica_query_result:
    :type deployed_service_replica_query_result:
     ~azure.servicefabric.models.DeployedStatefulServiceReplicaInfo
    """

    _validation = {
        'service_kind': {'required': True},
    }

    _attribute_map = {
        'service_name': {'key': 'ServiceName', 'type': 'str'},
        'partition_id': {'key': 'PartitionId', 'type': 'str'},
        'current_service_operation': {'key': 'CurrentServiceOperation', 'type': 'str'},
        'current_service_operation_start_time_utc': {'key': 'CurrentServiceOperationStartTimeUtc', 'type': 'iso-8601'},
        'reported_load': {'key': 'ReportedLoad', 'type': '[LoadMetricReportInfo]'},
        'service_kind': {'key': 'ServiceKind', 'type': 'str'},
        'replica_id': {'key': 'ReplicaId', 'type': 'str'},
        'current_replicator_operation': {'key': 'CurrentReplicatorOperation', 'type': 'str'},
        'read_status': {'key': 'ReadStatus', 'type': 'str'},
        'write_status': {'key': 'WriteStatus', 'type': 'str'},
        'replicator_status': {'key': 'ReplicatorStatus', 'type': 'ReplicatorStatus'},
        'replica_status': {'key': 'ReplicaStatus', 'type': 'KeyValueStoreReplicaStatus'},
        'deployed_service_replica_query_result': {'key': 'DeployedServiceReplicaQueryResult', 'type': 'DeployedStatefulServiceReplicaInfo'},
    }

    def __init__(self, service_name=None, partition_id=None, current_service_operation=None, current_service_operation_start_time_utc=None, reported_load=None, replica_id=None, current_replicator_operation=None, read_status=None, write_status=None, replicator_status=None, replica_status=None, deployed_service_replica_query_result=None):
        super(DeployedStatefulServiceReplicaDetailInfo, self).__init__(service_name=service_name, partition_id=partition_id, current_service_operation=current_service_operation, current_service_operation_start_time_utc=current_service_operation_start_time_utc, reported_load=reported_load)
        self.replica_id = replica_id
        self.current_replicator_operation = current_replicator_operation
        self.read_status = read_status
        self.write_status = write_status
        self.replicator_status = replicator_status
        self.replica_status = replica_status
        self.deployed_service_replica_query_result = deployed_service_replica_query_result
        self.service_kind = 'Stateful'
