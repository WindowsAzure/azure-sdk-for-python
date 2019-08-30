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

try:
    from ._models_py3 import Capability
    from ._models_py3 import CassandraKeyspace
    from ._models_py3 import CassandraKeyspaceCreateUpdateParameters
    from ._models_py3 import CassandraKeyspaceResource
    from ._models_py3 import CassandraPartitionKey
    from ._models_py3 import CassandraSchema
    from ._models_py3 import CassandraTable
    from ._models_py3 import CassandraTableCreateUpdateParameters
    from ._models_py3 import CassandraTableResource
    from ._models_py3 import ClusterKey
    from ._models_py3 import Column
    from ._models_py3 import ConflictResolutionPolicy
    from ._models_py3 import ConsistencyPolicy
    from ._models_py3 import ContainerPartitionKey
    from ._models_py3 import DatabaseAccount
    from ._models_py3 import DatabaseAccountConnectionString
    from ._models_py3 import DatabaseAccountCreateUpdateParameters
    from ._models_py3 import DatabaseAccountListConnectionStringsResult
    from ._models_py3 import DatabaseAccountListKeysResult
    from ._models_py3 import DatabaseAccountListReadOnlyKeysResult
    from ._models_py3 import DatabaseAccountPatchParameters
    from ._models_py3 import DatabaseAccountRegenerateKeyParameters
    from ._models_py3 import ErrorResponse, ErrorResponseException
    from ._models_py3 import ExcludedPath
    from ._models_py3 import ExtendedResourceProperties
    from ._models_py3 import FailoverPolicies
    from ._models_py3 import FailoverPolicy
    from ._models_py3 import GremlinDatabase
    from ._models_py3 import GremlinDatabaseCreateUpdateParameters
    from ._models_py3 import GremlinDatabaseResource
    from ._models_py3 import GremlinGraph
    from ._models_py3 import GremlinGraphCreateUpdateParameters
    from ._models_py3 import GremlinGraphResource
    from ._models_py3 import IncludedPath
    from ._models_py3 import Indexes
    from ._models_py3 import IndexingPolicy
    from ._models_py3 import Location
    from ._models_py3 import Metric
    from ._models_py3 import MetricAvailability
    from ._models_py3 import MetricDefinition
    from ._models_py3 import MetricName
    from ._models_py3 import MetricValue
    from ._models_py3 import MongoDBCollection
    from ._models_py3 import MongoDBCollectionCreateUpdateParameters
    from ._models_py3 import MongoDBCollectionResource
    from ._models_py3 import MongoDBDatabase
    from ._models_py3 import MongoDBDatabaseCreateUpdateParameters
    from ._models_py3 import MongoDBDatabaseResource
    from ._models_py3 import MongoIndex
    from ._models_py3 import MongoIndexKeys
    from ._models_py3 import MongoIndexOptions
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import PartitionMetric
    from ._models_py3 import PartitionUsage
    from ._models_py3 import PercentileMetric
    from ._models_py3 import PercentileMetricValue
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateEndpointProperty
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkResourceListResult
    from ._models_py3 import PrivateLinkResourceProperties
    from ._models_py3 import PrivateLinkServiceConnectionStateProperty
    from ._models_py3 import RegionForOnlineOffline
    from ._models_py3 import Resource
    from ._models_py3 import SqlContainer
    from ._models_py3 import SqlContainerCreateUpdateParameters
    from ._models_py3 import SqlContainerResource
    from ._models_py3 import SqlDatabase
    from ._models_py3 import SqlDatabaseCreateUpdateParameters
    from ._models_py3 import SqlDatabaseResource
    from ._models_py3 import Table
    from ._models_py3 import TableCreateUpdateParameters
    from ._models_py3 import TableResource
    from ._models_py3 import Throughput
    from ._models_py3 import ThroughputResource
    from ._models_py3 import ThroughputUpdateParameters
    from ._models_py3 import UniqueKey
    from ._models_py3 import UniqueKeyPolicy
    from ._models_py3 import Usage
    from ._models_py3 import VirtualNetworkRule
except (SyntaxError, ImportError):
    from ._models import Capability
    from ._models import CassandraKeyspace
    from ._models import CassandraKeyspaceCreateUpdateParameters
    from ._models import CassandraKeyspaceResource
    from ._models import CassandraPartitionKey
    from ._models import CassandraSchema
    from ._models import CassandraTable
    from ._models import CassandraTableCreateUpdateParameters
    from ._models import CassandraTableResource
    from ._models import ClusterKey
    from ._models import Column
    from ._models import ConflictResolutionPolicy
    from ._models import ConsistencyPolicy
    from ._models import ContainerPartitionKey
    from ._models import DatabaseAccount
    from ._models import DatabaseAccountConnectionString
    from ._models import DatabaseAccountCreateUpdateParameters
    from ._models import DatabaseAccountListConnectionStringsResult
    from ._models import DatabaseAccountListKeysResult
    from ._models import DatabaseAccountListReadOnlyKeysResult
    from ._models import DatabaseAccountPatchParameters
    from ._models import DatabaseAccountRegenerateKeyParameters
    from ._models import ErrorResponse, ErrorResponseException
    from ._models import ExcludedPath
    from ._models import ExtendedResourceProperties
    from ._models import FailoverPolicies
    from ._models import FailoverPolicy
    from ._models import GremlinDatabase
    from ._models import GremlinDatabaseCreateUpdateParameters
    from ._models import GremlinDatabaseResource
    from ._models import GremlinGraph
    from ._models import GremlinGraphCreateUpdateParameters
    from ._models import GremlinGraphResource
    from ._models import IncludedPath
    from ._models import Indexes
    from ._models import IndexingPolicy
    from ._models import Location
    from ._models import Metric
    from ._models import MetricAvailability
    from ._models import MetricDefinition
    from ._models import MetricName
    from ._models import MetricValue
    from ._models import MongoDBCollection
    from ._models import MongoDBCollectionCreateUpdateParameters
    from ._models import MongoDBCollectionResource
    from ._models import MongoDBDatabase
    from ._models import MongoDBDatabaseCreateUpdateParameters
    from ._models import MongoDBDatabaseResource
    from ._models import MongoIndex
    from ._models import MongoIndexKeys
    from ._models import MongoIndexOptions
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import PartitionMetric
    from ._models import PartitionUsage
    from ._models import PercentileMetric
    from ._models import PercentileMetricValue
    from ._models import PrivateEndpointConnection
    from ._models import PrivateEndpointProperty
    from ._models import PrivateLinkResource
    from ._models import PrivateLinkResourceListResult
    from ._models import PrivateLinkResourceProperties
    from ._models import PrivateLinkServiceConnectionStateProperty
    from ._models import RegionForOnlineOffline
    from ._models import Resource
    from ._models import SqlContainer
    from ._models import SqlContainerCreateUpdateParameters
    from ._models import SqlContainerResource
    from ._models import SqlDatabase
    from ._models import SqlDatabaseCreateUpdateParameters
    from ._models import SqlDatabaseResource
    from ._models import Table
    from ._models import TableCreateUpdateParameters
    from ._models import TableResource
    from ._models import Throughput
    from ._models import ThroughputResource
    from ._models import ThroughputUpdateParameters
    from ._models import UniqueKey
    from ._models import UniqueKeyPolicy
    from ._models import Usage
    from ._models import VirtualNetworkRule
from ._paged_models import CassandraKeyspacePaged
from ._paged_models import CassandraTablePaged
from ._paged_models import DatabaseAccountPaged
from ._paged_models import GremlinDatabasePaged
from ._paged_models import GremlinGraphPaged
from ._paged_models import MetricDefinitionPaged
from ._paged_models import MetricPaged
from ._paged_models import MongoDBCollectionPaged
from ._paged_models import MongoDBDatabasePaged
from ._paged_models import OperationPaged
from ._paged_models import PartitionMetricPaged
from ._paged_models import PartitionUsagePaged
from ._paged_models import PercentileMetricPaged
from ._paged_models import SqlContainerPaged
from ._paged_models import SqlDatabasePaged
from ._paged_models import TablePaged
from ._paged_models import UsagePaged
from ._cosmos_db_enums import (
    DatabaseAccountKind,
    DatabaseAccountOfferType,
    DefaultConsistencyLevel,
    ConnectorOffer,
    IndexingMode,
    DataType,
    IndexKind,
    PartitionKind,
    ConflictResolutionMode,
    KeyKind,
    UnitType,
    PrimaryAggregationType,
)

__all__ = [
    'Capability',
    'CassandraKeyspace',
    'CassandraKeyspaceCreateUpdateParameters',
    'CassandraKeyspaceResource',
    'CassandraPartitionKey',
    'CassandraSchema',
    'CassandraTable',
    'CassandraTableCreateUpdateParameters',
    'CassandraTableResource',
    'ClusterKey',
    'Column',
    'ConflictResolutionPolicy',
    'ConsistencyPolicy',
    'ContainerPartitionKey',
    'DatabaseAccount',
    'DatabaseAccountConnectionString',
    'DatabaseAccountCreateUpdateParameters',
    'DatabaseAccountListConnectionStringsResult',
    'DatabaseAccountListKeysResult',
    'DatabaseAccountListReadOnlyKeysResult',
    'DatabaseAccountPatchParameters',
    'DatabaseAccountRegenerateKeyParameters',
    'ErrorResponse', 'ErrorResponseException',
    'ExcludedPath',
    'ExtendedResourceProperties',
    'FailoverPolicies',
    'FailoverPolicy',
    'GremlinDatabase',
    'GremlinDatabaseCreateUpdateParameters',
    'GremlinDatabaseResource',
    'GremlinGraph',
    'GremlinGraphCreateUpdateParameters',
    'GremlinGraphResource',
    'IncludedPath',
    'Indexes',
    'IndexingPolicy',
    'Location',
    'Metric',
    'MetricAvailability',
    'MetricDefinition',
    'MetricName',
    'MetricValue',
    'MongoDBCollection',
    'MongoDBCollectionCreateUpdateParameters',
    'MongoDBCollectionResource',
    'MongoDBDatabase',
    'MongoDBDatabaseCreateUpdateParameters',
    'MongoDBDatabaseResource',
    'MongoIndex',
    'MongoIndexKeys',
    'MongoIndexOptions',
    'Operation',
    'OperationDisplay',
    'PartitionMetric',
    'PartitionUsage',
    'PercentileMetric',
    'PercentileMetricValue',
    'PrivateEndpointConnection',
    'PrivateEndpointProperty',
    'PrivateLinkResource',
    'PrivateLinkResourceListResult',
    'PrivateLinkResourceProperties',
    'PrivateLinkServiceConnectionStateProperty',
    'RegionForOnlineOffline',
    'Resource',
    'SqlContainer',
    'SqlContainerCreateUpdateParameters',
    'SqlContainerResource',
    'SqlDatabase',
    'SqlDatabaseCreateUpdateParameters',
    'SqlDatabaseResource',
    'Table',
    'TableCreateUpdateParameters',
    'TableResource',
    'Throughput',
    'ThroughputResource',
    'ThroughputUpdateParameters',
    'UniqueKey',
    'UniqueKeyPolicy',
    'Usage',
    'VirtualNetworkRule',
    'DatabaseAccountPaged',
    'MetricPaged',
    'UsagePaged',
    'MetricDefinitionPaged',
    'SqlDatabasePaged',
    'SqlContainerPaged',
    'MongoDBDatabasePaged',
    'MongoDBCollectionPaged',
    'TablePaged',
    'CassandraKeyspacePaged',
    'CassandraTablePaged',
    'GremlinDatabasePaged',
    'GremlinGraphPaged',
    'OperationPaged',
    'PercentileMetricPaged',
    'PartitionMetricPaged',
    'PartitionUsagePaged',
    'DatabaseAccountKind',
    'DatabaseAccountOfferType',
    'DefaultConsistencyLevel',
    'ConnectorOffer',
    'IndexingMode',
    'DataType',
    'IndexKind',
    'PartitionKind',
    'ConflictResolutionMode',
    'KeyKind',
    'UnitType',
    'PrimaryAggregationType',
]
