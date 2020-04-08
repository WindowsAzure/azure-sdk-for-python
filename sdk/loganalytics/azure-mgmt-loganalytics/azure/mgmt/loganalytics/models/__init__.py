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
    from ._models_py3 import AzureEntityResource
    from ._models_py3 import Cluster
    from ._models_py3 import ClusterErrorResponse, ClusterErrorResponseException
    from ._models_py3 import ClusterPatch
    from ._models_py3 import ClusterSku
    from ._models_py3 import DataExport
    from ._models_py3 import DataExportErrorResponse, DataExportErrorResponseException
    from ._models_py3 import DataSource
    from ._models_py3 import DataSourceFilter
    from ._models_py3 import ErrorAdditionalInfo
    from ._models_py3 import ErrorResponse
    from ._models_py3 import Identity
    from ._models_py3 import IntelligencePack
    from ._models_py3 import KeyVaultProperties
    from ._models_py3 import LinkedService
    from ._models_py3 import LinkedStorageAccountsResource
    from ._models_py3 import ManagementGroup
    from ._models_py3 import MetricName
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationStatus
    from ._models_py3 import PrivateLinkScopedResource
    from ._models_py3 import ProxyResource
    from ._models_py3 import Resource
    from ._models_py3 import SavedSearch
    from ._models_py3 import SavedSearchesListResult
    from ._models_py3 import SharedKeys
    from ._models_py3 import StorageAccount
    from ._models_py3 import StorageInsight
    from ._models_py3 import StorageInsightStatus
    from ._models_py3 import Tag
    from ._models_py3 import TrackedResource
    from ._models_py3 import UsageMetric
    from ._models_py3 import Workspace
    from ._models_py3 import WorkspacePatch
    from ._models_py3 import WorkspaceSku
except (SyntaxError, ImportError):
    from ._models import AzureEntityResource
    from ._models import Cluster
    from ._models import ClusterErrorResponse, ClusterErrorResponseException
    from ._models import ClusterPatch
    from ._models import ClusterSku
    from ._models import DataExport
    from ._models import DataExportErrorResponse, DataExportErrorResponseException
    from ._models import DataSource
    from ._models import DataSourceFilter
    from ._models import ErrorAdditionalInfo
    from ._models import ErrorResponse
    from ._models import Identity
    from ._models import IntelligencePack
    from ._models import KeyVaultProperties
    from ._models import LinkedService
    from ._models import LinkedStorageAccountsResource
    from ._models import ManagementGroup
    from ._models import MetricName
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import OperationStatus
    from ._models import PrivateLinkScopedResource
    from ._models import ProxyResource
    from ._models import Resource
    from ._models import SavedSearch
    from ._models import SavedSearchesListResult
    from ._models import SharedKeys
    from ._models import StorageAccount
    from ._models import StorageInsight
    from ._models import StorageInsightStatus
    from ._models import Tag
    from ._models import TrackedResource
    from ._models import UsageMetric
    from ._models import Workspace
    from ._models import WorkspacePatch
    from ._models import WorkspaceSku
from ._paged_models import ClusterPaged
from ._paged_models import DataExportPaged
from ._paged_models import DataSourcePaged
from ._paged_models import LinkedServicePaged
from ._paged_models import LinkedStorageAccountsResourcePaged
from ._paged_models import ManagementGroupPaged
from ._paged_models import OperationPaged
from ._paged_models import StorageInsightPaged
from ._paged_models import UsageMetricPaged
from ._paged_models import WorkspacePaged
from ._operational_insights_management_client_enums import (
    Type,
    DataSourceKind,
    DataSourceType,
    WorkspaceSkuNameEnum,
    EntityStatus,
    PublicNetworkAccessType,
    ClusterSkuNameEnum,
    IdentityType,
    StorageInsightState,
)

__all__ = [
    'AzureEntityResource',
    'Cluster',
    'ClusterErrorResponse', 'ClusterErrorResponseException',
    'ClusterPatch',
    'ClusterSku',
    'DataExport',
    'DataExportErrorResponse', 'DataExportErrorResponseException',
    'DataSource',
    'DataSourceFilter',
    'ErrorAdditionalInfo',
    'ErrorResponse',
    'Identity',
    'IntelligencePack',
    'KeyVaultProperties',
    'LinkedService',
    'LinkedStorageAccountsResource',
    'ManagementGroup',
    'MetricName',
    'Operation',
    'OperationDisplay',
    'OperationStatus',
    'PrivateLinkScopedResource',
    'ProxyResource',
    'Resource',
    'SavedSearch',
    'SavedSearchesListResult',
    'SharedKeys',
    'StorageAccount',
    'StorageInsight',
    'StorageInsightStatus',
    'Tag',
    'TrackedResource',
    'UsageMetric',
    'Workspace',
    'WorkspacePatch',
    'WorkspaceSku',
    'DataExportPaged',
    'DataSourcePaged',
    'ManagementGroupPaged',
    'UsageMetricPaged',
    'WorkspacePaged',
    'LinkedServicePaged',
    'LinkedStorageAccountsResourcePaged',
    'OperationPaged',
    'ClusterPaged',
    'StorageInsightPaged',
    'Type',
    'DataSourceKind',
    'DataSourceType',
    'WorkspaceSkuNameEnum',
    'EntityStatus',
    'PublicNetworkAccessType',
    'ClusterSkuNameEnum',
    'IdentityType',
    'StorageInsightState',
]
