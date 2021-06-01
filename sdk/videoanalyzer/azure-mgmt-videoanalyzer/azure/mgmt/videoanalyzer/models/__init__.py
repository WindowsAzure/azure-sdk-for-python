# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AccessPolicyEntity
    from ._models_py3 import AccessPolicyEntityCollection
    from ._models_py3 import AccountEncryption
    from ._models_py3 import AuthenticationBase
    from ._models_py3 import CheckNameAvailabilityRequest
    from ._models_py3 import CheckNameAvailabilityResponse
    from ._models_py3 import EccTokenKey
    from ._models_py3 import EdgeModuleEntity
    from ._models_py3 import EdgeModuleEntityCollection
    from ._models_py3 import EdgeModuleProvisioningToken
    from ._models_py3 import Endpoint
    from ._models_py3 import ErrorAdditionalInfo
    from ._models_py3 import ErrorDetail
    from ._models_py3 import ErrorResponse
    from ._models_py3 import JwtAuthentication
    from ._models_py3 import KeyVaultProperties
    from ._models_py3 import ListProvisioningTokenInput
    from ._models_py3 import LogSpecification
    from ._models_py3 import MetricDimension
    from ._models_py3 import MetricSpecification
    from ._models_py3 import Operation
    from ._models_py3 import OperationCollection
    from ._models_py3 import OperationDisplay
    from ._models_py3 import Properties
    from ._models_py3 import ProxyResource
    from ._models_py3 import Resource
    from ._models_py3 import ResourceIdentity
    from ._models_py3 import RsaTokenKey
    from ._models_py3 import ServiceSpecification
    from ._models_py3 import StorageAccount
    from ._models_py3 import SyncStorageKeysInput
    from ._models_py3 import SystemData
    from ._models_py3 import TokenClaim
    from ._models_py3 import TokenKey
    from ._models_py3 import TrackedResource
    from ._models_py3 import UserAssignedManagedIdentity
    from ._models_py3 import VideoAnalyzer
    from ._models_py3 import VideoAnalyzerCollection
    from ._models_py3 import VideoAnalyzerIdentity
    from ._models_py3 import VideoAnalyzerProperties
    from ._models_py3 import VideoAnalyzerPropertiesUpdate
    from ._models_py3 import VideoAnalyzerUpdate
    from ._models_py3 import VideoEntity
    from ._models_py3 import VideoEntityCollection
    from ._models_py3 import VideoFlags
    from ._models_py3 import VideoMediaInfo
    from ._models_py3 import VideoStreaming
    from ._models_py3 import VideoStreamingToken
except (SyntaxError, ImportError):
    from ._models import AccessPolicyEntity  # type: ignore
    from ._models import AccessPolicyEntityCollection  # type: ignore
    from ._models import AccountEncryption  # type: ignore
    from ._models import AuthenticationBase  # type: ignore
    from ._models import CheckNameAvailabilityRequest  # type: ignore
    from ._models import CheckNameAvailabilityResponse  # type: ignore
    from ._models import EccTokenKey  # type: ignore
    from ._models import EdgeModuleEntity  # type: ignore
    from ._models import EdgeModuleEntityCollection  # type: ignore
    from ._models import EdgeModuleProvisioningToken  # type: ignore
    from ._models import Endpoint  # type: ignore
    from ._models import ErrorAdditionalInfo  # type: ignore
    from ._models import ErrorDetail  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import JwtAuthentication  # type: ignore
    from ._models import KeyVaultProperties  # type: ignore
    from ._models import ListProvisioningTokenInput  # type: ignore
    from ._models import LogSpecification  # type: ignore
    from ._models import MetricDimension  # type: ignore
    from ._models import MetricSpecification  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationCollection  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import Properties  # type: ignore
    from ._models import ProxyResource  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceIdentity  # type: ignore
    from ._models import RsaTokenKey  # type: ignore
    from ._models import ServiceSpecification  # type: ignore
    from ._models import StorageAccount  # type: ignore
    from ._models import SyncStorageKeysInput  # type: ignore
    from ._models import SystemData  # type: ignore
    from ._models import TokenClaim  # type: ignore
    from ._models import TokenKey  # type: ignore
    from ._models import TrackedResource  # type: ignore
    from ._models import UserAssignedManagedIdentity  # type: ignore
    from ._models import VideoAnalyzer  # type: ignore
    from ._models import VideoAnalyzerCollection  # type: ignore
    from ._models import VideoAnalyzerIdentity  # type: ignore
    from ._models import VideoAnalyzerProperties  # type: ignore
    from ._models import VideoAnalyzerPropertiesUpdate  # type: ignore
    from ._models import VideoAnalyzerUpdate  # type: ignore
    from ._models import VideoEntity  # type: ignore
    from ._models import VideoEntityCollection  # type: ignore
    from ._models import VideoFlags  # type: ignore
    from ._models import VideoMediaInfo  # type: ignore
    from ._models import VideoStreaming  # type: ignore
    from ._models import VideoStreamingToken  # type: ignore

from ._video_analyzer_enums import (
    AccessPolicyEccAlgo,
    AccessPolicyRole,
    AccessPolicyRsaAlgo,
    AccountEncryptionKeyType,
    ActionType,
    CheckNameAvailabilityReason,
    CreatedByType,
    MetricAggregationType,
    MetricUnit,
    VideoAnalyzerEndpointType,
    VideoType,
)

__all__ = [
    'AccessPolicyEntity',
    'AccessPolicyEntityCollection',
    'AccountEncryption',
    'AuthenticationBase',
    'CheckNameAvailabilityRequest',
    'CheckNameAvailabilityResponse',
    'EccTokenKey',
    'EdgeModuleEntity',
    'EdgeModuleEntityCollection',
    'EdgeModuleProvisioningToken',
    'Endpoint',
    'ErrorAdditionalInfo',
    'ErrorDetail',
    'ErrorResponse',
    'JwtAuthentication',
    'KeyVaultProperties',
    'ListProvisioningTokenInput',
    'LogSpecification',
    'MetricDimension',
    'MetricSpecification',
    'Operation',
    'OperationCollection',
    'OperationDisplay',
    'Properties',
    'ProxyResource',
    'Resource',
    'ResourceIdentity',
    'RsaTokenKey',
    'ServiceSpecification',
    'StorageAccount',
    'SyncStorageKeysInput',
    'SystemData',
    'TokenClaim',
    'TokenKey',
    'TrackedResource',
    'UserAssignedManagedIdentity',
    'VideoAnalyzer',
    'VideoAnalyzerCollection',
    'VideoAnalyzerIdentity',
    'VideoAnalyzerProperties',
    'VideoAnalyzerPropertiesUpdate',
    'VideoAnalyzerUpdate',
    'VideoEntity',
    'VideoEntityCollection',
    'VideoFlags',
    'VideoMediaInfo',
    'VideoStreaming',
    'VideoStreamingToken',
    'AccessPolicyEccAlgo',
    'AccessPolicyRole',
    'AccessPolicyRsaAlgo',
    'AccountEncryptionKeyType',
    'ActionType',
    'CheckNameAvailabilityReason',
    'CreatedByType',
    'MetricAggregationType',
    'MetricUnit',
    'VideoAnalyzerEndpointType',
    'VideoType',
]
