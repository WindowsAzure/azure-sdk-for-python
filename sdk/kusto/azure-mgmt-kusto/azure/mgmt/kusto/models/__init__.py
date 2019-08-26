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
    from ._models_py3 import AzureCapacity
    from ._models_py3 import AzureEntityResource
    from ._models_py3 import AzureResourceSku
    from ._models_py3 import AzureSku
    from ._models_py3 import CheckNameResult
    from ._models_py3 import Cluster
    from ._models_py3 import ClusterCheckNameRequest
    from ._models_py3 import ClusterUpdate
    from ._models_py3 import Database
    from ._models_py3 import DatabaseCheckNameRequest
    from ._models_py3 import DatabasePrincipal
    from ._models_py3 import DatabasePrincipalListRequest
    from ._models_py3 import DatabasePrincipalListResult
    from ._models_py3 import DatabaseStatistics
    from ._models_py3 import DatabaseUpdate
    from ._models_py3 import DataConnection
    from ._models_py3 import DataConnectionCheckNameRequest
    from ._models_py3 import DataConnectionValidation
    from ._models_py3 import DataConnectionValidationListResult
    from ._models_py3 import DataConnectionValidationResult
    from ._models_py3 import EventGridDataConnection
    from ._models_py3 import EventHubDataConnection
    from ._models_py3 import IotHubDataConnection
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OptimizedAutoscale
    from ._models_py3 import ProxyResource
    from ._models_py3 import Resource
    from ._models_py3 import SkuDescription
    from ._models_py3 import SkuLocationInfoItem
    from ._models_py3 import TrackedResource
    from ._models_py3 import TrustedExternalTenant
    from ._models_py3 import VirtualNetworkConfiguration
except (SyntaxError, ImportError):
    from ._models import AzureCapacity
    from ._models import AzureEntityResource
    from ._models import AzureResourceSku
    from ._models import AzureSku
    from ._models import CheckNameResult
    from ._models import Cluster
    from ._models import ClusterCheckNameRequest
    from ._models import ClusterUpdate
    from ._models import Database
    from ._models import DatabaseCheckNameRequest
    from ._models import DatabasePrincipal
    from ._models import DatabasePrincipalListRequest
    from ._models import DatabasePrincipalListResult
    from ._models import DatabaseStatistics
    from ._models import DatabaseUpdate
    from ._models import DataConnection
    from ._models import DataConnectionCheckNameRequest
    from ._models import DataConnectionValidation
    from ._models import DataConnectionValidationListResult
    from ._models import DataConnectionValidationResult
    from ._models import EventGridDataConnection
    from ._models import EventHubDataConnection
    from ._models import IotHubDataConnection
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import OptimizedAutoscale
    from ._models import ProxyResource
    from ._models import Resource
    from ._models import SkuDescription
    from ._models import SkuLocationInfoItem
    from ._models import TrackedResource
    from ._models import TrustedExternalTenant
    from ._models import VirtualNetworkConfiguration
from ._paged_models import AzureResourceSkuPaged
from ._paged_models import ClusterPaged
from ._paged_models import DatabasePaged
from ._paged_models import DatabasePrincipalPaged
from ._paged_models import DataConnectionPaged
from ._paged_models import OperationPaged
from ._paged_models import SkuDescriptionPaged
from ._kusto_management_client_enums import (
    State,
    ProvisioningState,
    AzureSkuName,
    AzureSkuTier,
    AzureScaleType,
    DataFormat,
    DatabasePrincipalRole,
    DatabasePrincipalType,
    Reason,
)

__all__ = [
    'AzureCapacity',
    'AzureEntityResource',
    'AzureResourceSku',
    'AzureSku',
    'CheckNameResult',
    'Cluster',
    'ClusterCheckNameRequest',
    'ClusterUpdate',
    'Database',
    'DatabaseCheckNameRequest',
    'DatabasePrincipal',
    'DatabasePrincipalListRequest',
    'DatabasePrincipalListResult',
    'DatabaseStatistics',
    'DatabaseUpdate',
    'DataConnection',
    'DataConnectionCheckNameRequest',
    'DataConnectionValidation',
    'DataConnectionValidationListResult',
    'DataConnectionValidationResult',
    'EventGridDataConnection',
    'EventHubDataConnection',
    'IotHubDataConnection',
    'Operation',
    'OperationDisplay',
    'OptimizedAutoscale',
    'ProxyResource',
    'Resource',
    'SkuDescription',
    'SkuLocationInfoItem',
    'TrackedResource',
    'TrustedExternalTenant',
    'VirtualNetworkConfiguration',
    'ClusterPaged',
    'SkuDescriptionPaged',
    'AzureResourceSkuPaged',
    'DatabasePaged',
    'DatabasePrincipalPaged',
    'DataConnectionPaged',
    'OperationPaged',
    'State',
    'ProvisioningState',
    'AzureSkuName',
    'AzureSkuTier',
    'AzureScaleType',
    'DataFormat',
    'DatabasePrincipalRole',
    'DatabasePrincipalType',
    'Reason',
]
