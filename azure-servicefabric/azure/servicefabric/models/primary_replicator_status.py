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

from .replicator_status import ReplicatorStatus


class PrimaryReplicatorStatus(ReplicatorStatus):
    """PrimaryReplicatorStatus.

    :param kind: Constant filled by server.
    :type kind: str
    :param replication_queue_status:
    :type replication_queue_status:
     ~azure.servicefabric.models.ReplicatorQueueStatus
    :param remote_replicators:
    :type remote_replicators:
     list[~azure.servicefabric.models.RemoteReplicatorStatus]
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'Kind', 'type': 'str'},
        'replication_queue_status': {'key': 'ReplicationQueueStatus', 'type': 'ReplicatorQueueStatus'},
        'remote_replicators': {'key': 'RemoteReplicators', 'type': '[RemoteReplicatorStatus]'},
    }

    def __init__(self, replication_queue_status=None, remote_replicators=None):
        super(PrimaryReplicatorStatus, self).__init__()
        self.replication_queue_status = replication_queue_status
        self.remote_replicators = remote_replicators
        self.kind = 'Primary'
