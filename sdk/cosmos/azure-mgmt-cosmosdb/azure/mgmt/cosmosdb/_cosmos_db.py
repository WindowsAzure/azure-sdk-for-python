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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer

from ._configuration import CosmosDBConfiguration
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
from .operations import PrivateLinkResourcesOperations
from .operations import PrivateEndpointConnectionsOperations
from . import models


class CosmosDB(SDKClient):
    """Azure Cosmos DB Database Service Resource Provider REST API

    :ivar config: Configuration for client.
    :vartype config: CosmosDBConfiguration

    :ivar database_accounts: DatabaseAccounts operations
    :vartype database_accounts: azure.mgmt.cosmosdb.operations.DatabaseAccountsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.cosmosdb.operations.Operations
    :ivar database: Database operations
    :vartype database: azure.mgmt.cosmosdb.operations.DatabaseOperations
    :ivar collection: Collection operations
    :vartype collection: azure.mgmt.cosmosdb.operations.CollectionOperations
    :ivar collection_region: CollectionRegion operations
    :vartype collection_region: azure.mgmt.cosmosdb.operations.CollectionRegionOperations
    :ivar database_account_region: DatabaseAccountRegion operations
    :vartype database_account_region: azure.mgmt.cosmosdb.operations.DatabaseAccountRegionOperations
    :ivar percentile_source_target: PercentileSourceTarget operations
    :vartype percentile_source_target: azure.mgmt.cosmosdb.operations.PercentileSourceTargetOperations
    :ivar percentile_target: PercentileTarget operations
    :vartype percentile_target: azure.mgmt.cosmosdb.operations.PercentileTargetOperations
    :ivar percentile: Percentile operations
    :vartype percentile: azure.mgmt.cosmosdb.operations.PercentileOperations
    :ivar collection_partition_region: CollectionPartitionRegion operations
    :vartype collection_partition_region: azure.mgmt.cosmosdb.operations.CollectionPartitionRegionOperations
    :ivar collection_partition: CollectionPartition operations
    :vartype collection_partition: azure.mgmt.cosmosdb.operations.CollectionPartitionOperations
    :ivar partition_key_range_id: PartitionKeyRangeId operations
    :vartype partition_key_range_id: azure.mgmt.cosmosdb.operations.PartitionKeyRangeIdOperations
    :ivar partition_key_range_id_region: PartitionKeyRangeIdRegion operations
    :vartype partition_key_range_id_region: azure.mgmt.cosmosdb.operations.PartitionKeyRangeIdRegionOperations
    :ivar private_link_resources: PrivateLinkResources operations
    :vartype private_link_resources: azure.mgmt.cosmosdb.operations.PrivateLinkResourcesOperations
    :ivar private_endpoint_connections: PrivateEndpointConnections operations
    :vartype private_endpoint_connections: azure.mgmt.cosmosdb.operations.PrivateEndpointConnectionsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = CosmosDBConfiguration(credentials, subscription_id, base_url)
        super(CosmosDB, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.database_accounts = DatabaseAccountsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database = DatabaseOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.collection = CollectionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.collection_region = CollectionRegionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_account_region = DatabaseAccountRegionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.percentile_source_target = PercentileSourceTargetOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.percentile_target = PercentileTargetOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.percentile = PercentileOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.collection_partition_region = CollectionPartitionRegionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.collection_partition = CollectionPartitionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.partition_key_range_id = PartitionKeyRangeIdOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.partition_key_range_id_region = PartitionKeyRangeIdRegionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.private_link_resources = PrivateLinkResourcesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
