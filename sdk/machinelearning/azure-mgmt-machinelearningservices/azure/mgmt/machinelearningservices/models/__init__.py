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
    from ._models_py3 import AKS
    from ._models_py3 import AksComputeSecrets
    from ._models_py3 import AksNetworkingConfiguration
    from ._models_py3 import AKSProperties
    from ._models_py3 import AmlCompute
    from ._models_py3 import AmlComputeNodeInformation
    from ._models_py3 import AmlComputeNodesInformation
    from ._models_py3 import AmlComputeProperties
    from ._models_py3 import AmlUserFeature
    from ._models_py3 import ClusterUpdateParameters
    from ._models_py3 import Compute
    from ._models_py3 import ComputeNodesInformation
    from ._models_py3 import ComputeResource
    from ._models_py3 import ComputeSecrets
    from ._models_py3 import Databricks
    from ._models_py3 import DatabricksComputeSecrets
    from ._models_py3 import DatabricksProperties
    from ._models_py3 import DataFactory
    from ._models_py3 import DataLakeAnalytics
    from ._models_py3 import DataLakeAnalyticsProperties
    from ._models_py3 import EncryptionProperty
    from ._models_py3 import ErrorDetail
    from ._models_py3 import ErrorResponse, ErrorResponseException
    from ._models_py3 import HDInsight
    from ._models_py3 import HDInsightProperties
    from ._models_py3 import Identity
    from ._models_py3 import IdentityUserAssignedIdentitiesValue
    from ._models_py3 import KeyVaultProperties
    from ._models_py3 import ListWorkspaceKeysResult
    from ._models_py3 import MachineLearningServiceError, MachineLearningServiceErrorException
    from ._models_py3 import NodeStateCounts
    from ._models_py3 import NotebookListCredentialsResult
    from ._models_py3 import NotebookPreparationError
    from ._models_py3 import NotebookResourceInfo
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import Password
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkResourceListResult
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import QuotaBaseProperties
    from ._models_py3 import QuotaUpdateParameters
    from ._models_py3 import RegistryListCredentialsResult
    from ._models_py3 import Resource
    from ._models_py3 import ResourceId
    from ._models_py3 import ResourceName
    from ._models_py3 import ResourceQuota
    from ._models_py3 import ResourceSkuLocationInfo
    from ._models_py3 import ResourceSkuZoneDetails
    from ._models_py3 import Restriction
    from ._models_py3 import ScaleSettings
    from ._models_py3 import ServicePrincipalCredentials
    from ._models_py3 import SharedPrivateLinkResource
    from ._models_py3 import Sku
    from ._models_py3 import SKUCapability
    from ._models_py3 import SslConfiguration
    from ._models_py3 import SystemService
    from ._models_py3 import UpdateWorkspaceQuotas
    from ._models_py3 import UpdateWorkspaceQuotasResult
    from ._models_py3 import Usage
    from ._models_py3 import UsageName
    from ._models_py3 import UserAccountCredentials
    from ._models_py3 import VirtualMachine
    from ._models_py3 import VirtualMachineProperties
    from ._models_py3 import VirtualMachineSecrets
    from ._models_py3 import VirtualMachineSize
    from ._models_py3 import VirtualMachineSizeListResult
    from ._models_py3 import VirtualMachineSshCredentials
    from ._models_py3 import Workspace
    from ._models_py3 import WorkspaceSku
    from ._models_py3 import WorkspaceUpdateParameters
except (SyntaxError, ImportError):
    from ._models import AKS
    from ._models import AksComputeSecrets
    from ._models import AksNetworkingConfiguration
    from ._models import AKSProperties
    from ._models import AmlCompute
    from ._models import AmlComputeNodeInformation
    from ._models import AmlComputeNodesInformation
    from ._models import AmlComputeProperties
    from ._models import AmlUserFeature
    from ._models import ClusterUpdateParameters
    from ._models import Compute
    from ._models import ComputeNodesInformation
    from ._models import ComputeResource
    from ._models import ComputeSecrets
    from ._models import Databricks
    from ._models import DatabricksComputeSecrets
    from ._models import DatabricksProperties
    from ._models import DataFactory
    from ._models import DataLakeAnalytics
    from ._models import DataLakeAnalyticsProperties
    from ._models import EncryptionProperty
    from ._models import ErrorDetail
    from ._models import ErrorResponse, ErrorResponseException
    from ._models import HDInsight
    from ._models import HDInsightProperties
    from ._models import Identity
    from ._models import IdentityUserAssignedIdentitiesValue
    from ._models import KeyVaultProperties
    from ._models import ListWorkspaceKeysResult
    from ._models import MachineLearningServiceError, MachineLearningServiceErrorException
    from ._models import NodeStateCounts
    from ._models import NotebookListCredentialsResult
    from ._models import NotebookPreparationError
    from ._models import NotebookResourceInfo
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import Password
    from ._models import PrivateEndpoint
    from ._models import PrivateEndpointConnection
    from ._models import PrivateLinkResource
    from ._models import PrivateLinkResourceListResult
    from ._models import PrivateLinkServiceConnectionState
    from ._models import QuotaBaseProperties
    from ._models import QuotaUpdateParameters
    from ._models import RegistryListCredentialsResult
    from ._models import Resource
    from ._models import ResourceId
    from ._models import ResourceName
    from ._models import ResourceQuota
    from ._models import ResourceSkuLocationInfo
    from ._models import ResourceSkuZoneDetails
    from ._models import Restriction
    from ._models import ScaleSettings
    from ._models import ServicePrincipalCredentials
    from ._models import SharedPrivateLinkResource
    from ._models import Sku
    from ._models import SKUCapability
    from ._models import SslConfiguration
    from ._models import SystemService
    from ._models import UpdateWorkspaceQuotas
    from ._models import UpdateWorkspaceQuotasResult
    from ._models import Usage
    from ._models import UsageName
    from ._models import UserAccountCredentials
    from ._models import VirtualMachine
    from ._models import VirtualMachineProperties
    from ._models import VirtualMachineSecrets
    from ._models import VirtualMachineSize
    from ._models import VirtualMachineSizeListResult
    from ._models import VirtualMachineSshCredentials
    from ._models import Workspace
    from ._models import WorkspaceSku
    from ._models import WorkspaceUpdateParameters
from ._paged_models import AmlUserFeaturePaged
from ._paged_models import ComputeResourcePaged
from ._paged_models import OperationPaged
from ._paged_models import ResourceQuotaPaged
from ._paged_models import UsagePaged
from ._paged_models import WorkspacePaged
from ._paged_models import WorkspaceSkuPaged
from ._azure_machine_learning_workspaces_enums import (
    ProvisioningState,
    EncryptionStatus,
    PrivateEndpointServiceConnectionStatus,
    PrivateEndpointConnectionProvisioningState,
    UsageUnit,
    QuotaUnit,
    Status,
    ResourceIdentityType,
    VmPriority,
    RemoteLoginPortPublicAccess,
    AllocationState,
    NodeState,
    ComputeType,
    ReasonCode,
    UnderlyingResourceAction,
)

__all__ = [
    'AKS',
    'AksComputeSecrets',
    'AksNetworkingConfiguration',
    'AKSProperties',
    'AmlCompute',
    'AmlComputeNodeInformation',
    'AmlComputeNodesInformation',
    'AmlComputeProperties',
    'AmlUserFeature',
    'ClusterUpdateParameters',
    'Compute',
    'ComputeNodesInformation',
    'ComputeResource',
    'ComputeSecrets',
    'Databricks',
    'DatabricksComputeSecrets',
    'DatabricksProperties',
    'DataFactory',
    'DataLakeAnalytics',
    'DataLakeAnalyticsProperties',
    'EncryptionProperty',
    'ErrorDetail',
    'ErrorResponse', 'ErrorResponseException',
    'HDInsight',
    'HDInsightProperties',
    'Identity',
    'IdentityUserAssignedIdentitiesValue',
    'KeyVaultProperties',
    'ListWorkspaceKeysResult',
    'MachineLearningServiceError', 'MachineLearningServiceErrorException',
    'NodeStateCounts',
    'NotebookListCredentialsResult',
    'NotebookPreparationError',
    'NotebookResourceInfo',
    'Operation',
    'OperationDisplay',
    'Password',
    'PrivateEndpoint',
    'PrivateEndpointConnection',
    'PrivateLinkResource',
    'PrivateLinkResourceListResult',
    'PrivateLinkServiceConnectionState',
    'QuotaBaseProperties',
    'QuotaUpdateParameters',
    'RegistryListCredentialsResult',
    'Resource',
    'ResourceId',
    'ResourceName',
    'ResourceQuota',
    'ResourceSkuLocationInfo',
    'ResourceSkuZoneDetails',
    'Restriction',
    'ScaleSettings',
    'ServicePrincipalCredentials',
    'SharedPrivateLinkResource',
    'Sku',
    'SKUCapability',
    'SslConfiguration',
    'SystemService',
    'UpdateWorkspaceQuotas',
    'UpdateWorkspaceQuotasResult',
    'Usage',
    'UsageName',
    'UserAccountCredentials',
    'VirtualMachine',
    'VirtualMachineProperties',
    'VirtualMachineSecrets',
    'VirtualMachineSize',
    'VirtualMachineSizeListResult',
    'VirtualMachineSshCredentials',
    'Workspace',
    'WorkspaceSku',
    'WorkspaceUpdateParameters',
    'OperationPaged',
    'WorkspacePaged',
    'AmlUserFeaturePaged',
    'UsagePaged',
    'ResourceQuotaPaged',
    'ComputeResourcePaged',
    'WorkspaceSkuPaged',
    'ProvisioningState',
    'EncryptionStatus',
    'PrivateEndpointServiceConnectionStatus',
    'PrivateEndpointConnectionProvisioningState',
    'UsageUnit',
    'QuotaUnit',
    'Status',
    'ResourceIdentityType',
    'VmPriority',
    'RemoteLoginPortPublicAccess',
    'AllocationState',
    'NodeState',
    'ComputeType',
    'ReasonCode',
    'UnderlyingResourceAction',
]
