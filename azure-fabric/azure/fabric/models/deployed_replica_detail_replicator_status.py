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


class DeployedReplicaDetailReplicatorStatus(Model):
    """The status of the replicator.

    :param kind:
    :type kind: int
    :param replication_queue_status: The status of the replication queue
    :type replication_queue_status:
     :class:`DeployedReplicaDetailReplicatorStatusReplicationQueueStatus
     <azure.fabric.models.DeployedReplicaDetailReplicatorStatusReplicationQueueStatus>`
    """

    _attribute_map = {
        'kind': {'key': 'Kind', 'type': 'int'},
        'replication_queue_status': {'key': 'ReplicationQueueStatus', 'type': 'DeployedReplicaDetailReplicatorStatusReplicationQueueStatus'},
    }

    def __init__(self, kind=None, replication_queue_status=None):
        self.kind = kind
        self.replication_queue_status = replication_queue_status
