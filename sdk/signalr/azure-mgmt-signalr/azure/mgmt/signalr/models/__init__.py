# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import Dimension
    from ._models_py3 import ErrorAdditionalInfo
    from ._models_py3 import ErrorDetail
    from ._models_py3 import ErrorResponse
    from ._models_py3 import LogSpecification
    from ._models_py3 import ManagedIdentity
    from ._models_py3 import ManagedIdentitySettings
    from ._models_py3 import MetricSpecification
    from ._models_py3 import NameAvailability
    from ._models_py3 import NameAvailabilityParameters
    from ._models_py3 import NetworkACL
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationList
    from ._models_py3 import OperationProperties
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointACL
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateEndpointConnectionList
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkResourceList
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import ProxyResource
    from ._models_py3 import RegenerateKeyParameters
    from ._models_py3 import Resource
    from ._models_py3 import ResourceSku
    from ._models_py3 import ServerlessUpstreamSettings
    from ._models_py3 import ServiceSpecification
    from ._models_py3 import ShareablePrivateLinkResourceProperties
    from ._models_py3 import ShareablePrivateLinkResourceType
    from ._models_py3 import SharedPrivateLinkResource
    from ._models_py3 import SharedPrivateLinkResourceList
    from ._models_py3 import SignalRCorsSettings
    from ._models_py3 import SignalRFeature
    from ._models_py3 import SignalRKeys
    from ._models_py3 import SignalRNetworkACLs
    from ._models_py3 import SignalRResource
    from ._models_py3 import SignalRResourceList
    from ._models_py3 import SignalRTlsSettings
    from ._models_py3 import SignalRUsage
    from ._models_py3 import SignalRUsageList
    from ._models_py3 import SignalRUsageName
    from ._models_py3 import SystemData
    from ._models_py3 import TrackedResource
    from ._models_py3 import UpstreamAuthSettings
    from ._models_py3 import UpstreamTemplate
    from ._models_py3 import UserAssignedIdentityProperty
except (SyntaxError, ImportError):
    from ._models import Dimension  # type: ignore
    from ._models import ErrorAdditionalInfo  # type: ignore
    from ._models import ErrorDetail  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import LogSpecification  # type: ignore
    from ._models import ManagedIdentity  # type: ignore
    from ._models import ManagedIdentitySettings  # type: ignore
    from ._models import MetricSpecification  # type: ignore
    from ._models import NameAvailability  # type: ignore
    from ._models import NameAvailabilityParameters  # type: ignore
    from ._models import NetworkACL  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import OperationList  # type: ignore
    from ._models import OperationProperties  # type: ignore
    from ._models import PrivateEndpoint  # type: ignore
    from ._models import PrivateEndpointACL  # type: ignore
    from ._models import PrivateEndpointConnection  # type: ignore
    from ._models import PrivateEndpointConnectionList  # type: ignore
    from ._models import PrivateLinkResource  # type: ignore
    from ._models import PrivateLinkResourceList  # type: ignore
    from ._models import PrivateLinkServiceConnectionState  # type: ignore
    from ._models import ProxyResource  # type: ignore
    from ._models import RegenerateKeyParameters  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceSku  # type: ignore
    from ._models import ServerlessUpstreamSettings  # type: ignore
    from ._models import ServiceSpecification  # type: ignore
    from ._models import ShareablePrivateLinkResourceProperties  # type: ignore
    from ._models import ShareablePrivateLinkResourceType  # type: ignore
    from ._models import SharedPrivateLinkResource  # type: ignore
    from ._models import SharedPrivateLinkResourceList  # type: ignore
    from ._models import SignalRCorsSettings  # type: ignore
    from ._models import SignalRFeature  # type: ignore
    from ._models import SignalRKeys  # type: ignore
    from ._models import SignalRNetworkACLs  # type: ignore
    from ._models import SignalRResource  # type: ignore
    from ._models import SignalRResourceList  # type: ignore
    from ._models import SignalRTlsSettings  # type: ignore
    from ._models import SignalRUsage  # type: ignore
    from ._models import SignalRUsageList  # type: ignore
    from ._models import SignalRUsageName  # type: ignore
    from ._models import SystemData  # type: ignore
    from ._models import TrackedResource  # type: ignore
    from ._models import UpstreamAuthSettings  # type: ignore
    from ._models import UpstreamTemplate  # type: ignore
    from ._models import UserAssignedIdentityProperty  # type: ignore

from ._signal_rmanagement_client_enums import (
    ACLAction,
    CreatedByType,
    FeatureFlags,
    KeyType,
    ManagedIdentityType,
    PrivateLinkServiceConnectionStatus,
    ProvisioningState,
    ServiceKind,
    SharedPrivateLinkResourceStatus,
    SignalRRequestType,
    SignalRSkuTier,
    UpstreamAuthType,
)

__all__ = [
    'Dimension',
    'ErrorAdditionalInfo',
    'ErrorDetail',
    'ErrorResponse',
    'LogSpecification',
    'ManagedIdentity',
    'ManagedIdentitySettings',
    'MetricSpecification',
    'NameAvailability',
    'NameAvailabilityParameters',
    'NetworkACL',
    'Operation',
    'OperationDisplay',
    'OperationList',
    'OperationProperties',
    'PrivateEndpoint',
    'PrivateEndpointACL',
    'PrivateEndpointConnection',
    'PrivateEndpointConnectionList',
    'PrivateLinkResource',
    'PrivateLinkResourceList',
    'PrivateLinkServiceConnectionState',
    'ProxyResource',
    'RegenerateKeyParameters',
    'Resource',
    'ResourceSku',
    'ServerlessUpstreamSettings',
    'ServiceSpecification',
    'ShareablePrivateLinkResourceProperties',
    'ShareablePrivateLinkResourceType',
    'SharedPrivateLinkResource',
    'SharedPrivateLinkResourceList',
    'SignalRCorsSettings',
    'SignalRFeature',
    'SignalRKeys',
    'SignalRNetworkACLs',
    'SignalRResource',
    'SignalRResourceList',
    'SignalRTlsSettings',
    'SignalRUsage',
    'SignalRUsageList',
    'SignalRUsageName',
    'SystemData',
    'TrackedResource',
    'UpstreamAuthSettings',
    'UpstreamTemplate',
    'UserAssignedIdentityProperty',
    'ACLAction',
    'CreatedByType',
    'FeatureFlags',
    'KeyType',
    'ManagedIdentityType',
    'PrivateLinkServiceConnectionStatus',
    'ProvisioningState',
    'ServiceKind',
    'SharedPrivateLinkResourceStatus',
    'SignalRRequestType',
    'SignalRSkuTier',
    'UpstreamAuthType',
]
