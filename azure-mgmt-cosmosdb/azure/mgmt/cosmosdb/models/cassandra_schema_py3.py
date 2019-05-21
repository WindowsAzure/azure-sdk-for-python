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


class CassandraSchema(Model):
    """Cosmos DB Cassandra table schema.

    :param columns: List of Cassandra table columns.
    :type columns: list[~azure.mgmt.cosmosdb.models.Column]
    :param partition_keys: List of partition key.
    :type partition_keys:
     list[~azure.mgmt.cosmosdb.models.CassandraPartitionKey]
    :param cluster_keys: List of cluster key.
    :type cluster_keys: list[~azure.mgmt.cosmosdb.models.ClusterKey]
    """

    _attribute_map = {
        'columns': {'key': 'columns', 'type': '[Column]'},
        'partition_keys': {'key': 'partitionKeys', 'type': '[CassandraPartitionKey]'},
        'cluster_keys': {'key': 'clusterKeys', 'type': '[ClusterKey]'},
    }

    def __init__(self, *, columns=None, partition_keys=None, cluster_keys=None, **kwargs) -> None:
        super(CassandraSchema, self).__init__(**kwargs)
        self.columns = columns
        self.partition_keys = partition_keys
        self.cluster_keys = cluster_keys
