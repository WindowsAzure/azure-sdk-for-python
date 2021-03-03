# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.mgmt.core import ARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional

    from azure.core.credentials import TokenCredential

from ._configuration import CosmosDBManagementClientConfiguration
from .operations import DatabaseAccountsOperations
from .operations import Operations
from .operations import DatabaseOperations
from .operations import CollectionOperations
from .operations import CollectionRegionOperations
from .operations import DatabaseAccountRegionOperations
from .operations import PercentileSourceTargetOperations
from .operations import PercentileTargetOperations
from .operations import PercentileOperations
from .operations import CollectionPartitionRegionOperations
from .operations import CollectionPartitionOperations
from .operations import PartitionKeyRangeIdOperations
from .operations import PartitionKeyRangeIdRegionOperations
from .operations import SqlResourcesOperations
from .operations import MongoDBResourcesOperations
from .operations import TableResourcesOperations
from .operations import CassandraResourcesOperations
from .operations import GremlinResourcesOperations
from .operations import NotebookWorkspacesOperations
from .operations import PrivateLinkResourcesOperations
from .operations import PrivateEndpointConnectionsOperations
from . import models


class CosmosDBManagementClient(object):
    """Azure Cosmos DB Database Service Resource Provider REST API.

    :ivar database_accounts: DatabaseAccountsOperations operations
    :vartype database_accounts: azure.mgmt.cosmosdb.operations.DatabaseAccountsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.cosmosdb.operations.Operations
    :ivar database: DatabaseOperations operations
    :vartype database: azure.mgmt.cosmosdb.operations.DatabaseOperations
    :ivar collection: CollectionOperations operations
    :vartype collection: azure.mgmt.cosmosdb.operations.CollectionOperations
    :ivar collection_region: CollectionRegionOperations operations
    :vartype collection_region: azure.mgmt.cosmosdb.operations.CollectionRegionOperations
    :ivar database_account_region: DatabaseAccountRegionOperations operations
    :vartype database_account_region: azure.mgmt.cosmosdb.operations.DatabaseAccountRegionOperations
    :ivar percentile_source_target: PercentileSourceTargetOperations operations
    :vartype percentile_source_target: azure.mgmt.cosmosdb.operations.PercentileSourceTargetOperations
    :ivar percentile_target: PercentileTargetOperations operations
    :vartype percentile_target: azure.mgmt.cosmosdb.operations.PercentileTargetOperations
    :ivar percentile: PercentileOperations operations
    :vartype percentile: azure.mgmt.cosmosdb.operations.PercentileOperations
    :ivar collection_partition_region: CollectionPartitionRegionOperations operations
    :vartype collection_partition_region: azure.mgmt.cosmosdb.operations.CollectionPartitionRegionOperations
    :ivar collection_partition: CollectionPartitionOperations operations
    :vartype collection_partition: azure.mgmt.cosmosdb.operations.CollectionPartitionOperations
    :ivar partition_key_range_id: PartitionKeyRangeIdOperations operations
    :vartype partition_key_range_id: azure.mgmt.cosmosdb.operations.PartitionKeyRangeIdOperations
    :ivar partition_key_range_id_region: PartitionKeyRangeIdRegionOperations operations
    :vartype partition_key_range_id_region: azure.mgmt.cosmosdb.operations.PartitionKeyRangeIdRegionOperations
    :ivar sql_resources: SqlResourcesOperations operations
    :vartype sql_resources: azure.mgmt.cosmosdb.operations.SqlResourcesOperations
    :ivar mongo_db_resources: MongoDBResourcesOperations operations
    :vartype mongo_db_resources: azure.mgmt.cosmosdb.operations.MongoDBResourcesOperations
    :ivar table_resources: TableResourcesOperations operations
    :vartype table_resources: azure.mgmt.cosmosdb.operations.TableResourcesOperations
    :ivar cassandra_resources: CassandraResourcesOperations operations
    :vartype cassandra_resources: azure.mgmt.cosmosdb.operations.CassandraResourcesOperations
    :ivar gremlin_resources: GremlinResourcesOperations operations
    :vartype gremlin_resources: azure.mgmt.cosmosdb.operations.GremlinResourcesOperations
    :ivar notebook_workspaces: NotebookWorkspacesOperations operations
    :vartype notebook_workspaces: azure.mgmt.cosmosdb.operations.NotebookWorkspacesOperations
    :ivar private_link_resources: PrivateLinkResourcesOperations operations
    :vartype private_link_resources: azure.mgmt.cosmosdb.operations.PrivateLinkResourcesOperations
    :ivar private_endpoint_connections: PrivateEndpointConnectionsOperations operations
    :vartype private_endpoint_connections: azure.mgmt.cosmosdb.operations.PrivateEndpointConnectionsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The ID of the target subscription.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        base_url=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = CosmosDBManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.database_accounts = DatabaseAccountsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.database = DatabaseOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.collection = CollectionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.collection_region = CollectionRegionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.database_account_region = DatabaseAccountRegionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.percentile_source_target = PercentileSourceTargetOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.percentile_target = PercentileTargetOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.percentile = PercentileOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.collection_partition_region = CollectionPartitionRegionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.collection_partition = CollectionPartitionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.partition_key_range_id = PartitionKeyRangeIdOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.partition_key_range_id_region = PartitionKeyRangeIdRegionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.sql_resources = SqlResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.mongo_db_resources = MongoDBResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.table_resources = TableResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.cassandra_resources = CassandraResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.gremlin_resources = GremlinResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.notebook_workspaces = NotebookWorkspacesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_link_resources = PrivateLinkResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> CosmosDBManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
