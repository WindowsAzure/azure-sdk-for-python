# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AppResource
    from ._models_py3 import AppResourceCollection
    from ._models_py3 import AppResourceProperties
    from ._models_py3 import AvailableOperations
    from ._models_py3 import AvailableRuntimeVersions
    from ._models_py3 import BindingResource
    from ._models_py3 import BindingResourceCollection
    from ._models_py3 import BindingResourceProperties
    from ._models_py3 import CertificateProperties
    from ._models_py3 import CertificateResource
    from ._models_py3 import CertificateResourceCollection
    from ._models_py3 import CloudErrorBody
    from ._models_py3 import ClusterResourceProperties
    from ._models_py3 import ConfigServerGitProperty
    from ._models_py3 import ConfigServerProperties
    from ._models_py3 import ConfigServerSettings
    from ._models_py3 import CustomDomainProperties
    from ._models_py3 import CustomDomainResource
    from ._models_py3 import CustomDomainResourceCollection
    from ._models_py3 import CustomDomainValidatePayload
    from ._models_py3 import CustomDomainValidateResult
    from ._models_py3 import DeploymentInstance
    from ._models_py3 import DeploymentResource
    from ._models_py3 import DeploymentResourceCollection
    from ._models_py3 import DeploymentResourceProperties
    from ._models_py3 import DeploymentSettings
    from ._models_py3 import Error
    from ._models_py3 import GitPatternRepository
    from ._models_py3 import LogFileUrlResponse
    from ._models_py3 import LogSpecification
    from ._models_py3 import ManagedIdentityProperties
    from ._models_py3 import MetricDimension
    from ._models_py3 import MetricSpecification
    from ._models_py3 import NameAvailability
    from ._models_py3 import NameAvailabilityParameters
    from ._models_py3 import NetworkProfile
    from ._models_py3 import NetworkProfileOutboundIPs
    from ._models_py3 import OperationDetail
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationProperties
    from ._models_py3 import PersistentDisk
    from ._models_py3 import ProxyResource
    from ._models_py3 import RegenerateTestKeyRequestPayload
    from ._models_py3 import Resource
    from ._models_py3 import ResourceSku
    from ._models_py3 import ResourceSkuCapabilities
    from ._models_py3 import ResourceSkuCollection
    from ._models_py3 import ResourceSkuLocationInfo
    from ._models_py3 import ResourceSkuRestrictionInfo
    from ._models_py3 import ResourceSkuRestrictions
    from ._models_py3 import ResourceSkuZoneDetails
    from ._models_py3 import ResourceUploadDefinition
    from ._models_py3 import ServiceResource
    from ._models_py3 import ServiceResourceList
    from ._models_py3 import ServiceSpecification
    from ._models_py3 import Sku
    from ._models_py3 import SkuCapacity
    from ._models_py3 import SupportedRuntimeVersion
    from ._models_py3 import TemporaryDisk
    from ._models_py3 import TestKeys
    from ._models_py3 import TraceProperties
    from ._models_py3 import TrackedResource
    from ._models_py3 import UserSourceInfo
except (SyntaxError, ImportError):
    from ._models import AppResource  # type: ignore
    from ._models import AppResourceCollection  # type: ignore
    from ._models import AppResourceProperties  # type: ignore
    from ._models import AvailableOperations  # type: ignore
    from ._models import AvailableRuntimeVersions  # type: ignore
    from ._models import BindingResource  # type: ignore
    from ._models import BindingResourceCollection  # type: ignore
    from ._models import BindingResourceProperties  # type: ignore
    from ._models import CertificateProperties  # type: ignore
    from ._models import CertificateResource  # type: ignore
    from ._models import CertificateResourceCollection  # type: ignore
    from ._models import CloudErrorBody  # type: ignore
    from ._models import ClusterResourceProperties  # type: ignore
    from ._models import ConfigServerGitProperty  # type: ignore
    from ._models import ConfigServerProperties  # type: ignore
    from ._models import ConfigServerSettings  # type: ignore
    from ._models import CustomDomainProperties  # type: ignore
    from ._models import CustomDomainResource  # type: ignore
    from ._models import CustomDomainResourceCollection  # type: ignore
    from ._models import CustomDomainValidatePayload  # type: ignore
    from ._models import CustomDomainValidateResult  # type: ignore
    from ._models import DeploymentInstance  # type: ignore
    from ._models import DeploymentResource  # type: ignore
    from ._models import DeploymentResourceCollection  # type: ignore
    from ._models import DeploymentResourceProperties  # type: ignore
    from ._models import DeploymentSettings  # type: ignore
    from ._models import Error  # type: ignore
    from ._models import GitPatternRepository  # type: ignore
    from ._models import LogFileUrlResponse  # type: ignore
    from ._models import LogSpecification  # type: ignore
    from ._models import ManagedIdentityProperties  # type: ignore
    from ._models import MetricDimension  # type: ignore
    from ._models import MetricSpecification  # type: ignore
    from ._models import NameAvailability  # type: ignore
    from ._models import NameAvailabilityParameters  # type: ignore
    from ._models import NetworkProfile  # type: ignore
    from ._models import NetworkProfileOutboundIPs  # type: ignore
    from ._models import OperationDetail  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import OperationProperties  # type: ignore
    from ._models import PersistentDisk  # type: ignore
    from ._models import ProxyResource  # type: ignore
    from ._models import RegenerateTestKeyRequestPayload  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceSku  # type: ignore
    from ._models import ResourceSkuCapabilities  # type: ignore
    from ._models import ResourceSkuCollection  # type: ignore
    from ._models import ResourceSkuLocationInfo  # type: ignore
    from ._models import ResourceSkuRestrictionInfo  # type: ignore
    from ._models import ResourceSkuRestrictions  # type: ignore
    from ._models import ResourceSkuZoneDetails  # type: ignore
    from ._models import ResourceUploadDefinition  # type: ignore
    from ._models import ServiceResource  # type: ignore
    from ._models import ServiceResourceList  # type: ignore
    from ._models import ServiceSpecification  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import SkuCapacity  # type: ignore
    from ._models import SupportedRuntimeVersion  # type: ignore
    from ._models import TemporaryDisk  # type: ignore
    from ._models import TestKeys  # type: ignore
    from ._models import TraceProperties  # type: ignore
    from ._models import TrackedResource  # type: ignore
    from ._models import UserSourceInfo  # type: ignore

from ._app_platform_management_client_enums import (
    AppResourceProvisioningState,
    ConfigServerState,
    DeploymentResourceProvisioningState,
    DeploymentResourceStatus,
    ManagedIdentityType,
    ProvisioningState,
    ResourceSkuRestrictionsReasonCode,
    ResourceSkuRestrictionsType,
    RuntimeVersion,
    SkuScaleType,
    SupportedRuntimePlatform,
    SupportedRuntimeValue,
    TestKeyType,
    TraceProxyState,
    UserSourceType,
)

__all__ = [
    'AppResource',
    'AppResourceCollection',
    'AppResourceProperties',
    'AvailableOperations',
    'AvailableRuntimeVersions',
    'BindingResource',
    'BindingResourceCollection',
    'BindingResourceProperties',
    'CertificateProperties',
    'CertificateResource',
    'CertificateResourceCollection',
    'CloudErrorBody',
    'ClusterResourceProperties',
    'ConfigServerGitProperty',
    'ConfigServerProperties',
    'ConfigServerSettings',
    'CustomDomainProperties',
    'CustomDomainResource',
    'CustomDomainResourceCollection',
    'CustomDomainValidatePayload',
    'CustomDomainValidateResult',
    'DeploymentInstance',
    'DeploymentResource',
    'DeploymentResourceCollection',
    'DeploymentResourceProperties',
    'DeploymentSettings',
    'Error',
    'GitPatternRepository',
    'LogFileUrlResponse',
    'LogSpecification',
    'ManagedIdentityProperties',
    'MetricDimension',
    'MetricSpecification',
    'NameAvailability',
    'NameAvailabilityParameters',
    'NetworkProfile',
    'NetworkProfileOutboundIPs',
    'OperationDetail',
    'OperationDisplay',
    'OperationProperties',
    'PersistentDisk',
    'ProxyResource',
    'RegenerateTestKeyRequestPayload',
    'Resource',
    'ResourceSku',
    'ResourceSkuCapabilities',
    'ResourceSkuCollection',
    'ResourceSkuLocationInfo',
    'ResourceSkuRestrictionInfo',
    'ResourceSkuRestrictions',
    'ResourceSkuZoneDetails',
    'ResourceUploadDefinition',
    'ServiceResource',
    'ServiceResourceList',
    'ServiceSpecification',
    'Sku',
    'SkuCapacity',
    'SupportedRuntimeVersion',
    'TemporaryDisk',
    'TestKeys',
    'TraceProperties',
    'TrackedResource',
    'UserSourceInfo',
    'AppResourceProvisioningState',
    'ConfigServerState',
    'DeploymentResourceProvisioningState',
    'DeploymentResourceStatus',
    'ManagedIdentityType',
    'ProvisioningState',
    'ResourceSkuRestrictionsReasonCode',
    'ResourceSkuRestrictionsType',
    'RuntimeVersion',
    'SkuScaleType',
    'SupportedRuntimePlatform',
    'SupportedRuntimeValue',
    'TestKeyType',
    'TraceProxyState',
    'UserSourceType',
]
