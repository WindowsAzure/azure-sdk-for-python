# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import ApiKey
    from ._models_py3 import ApiKeyListResult
    from ._models_py3 import CheckNameAvailabilityParameters
    from ._models_py3 import ConfigurationStore
    from ._models_py3 import ConfigurationStoreListResult
    from ._models_py3 import ConfigurationStoreUpdateParameters
    from ._models_py3 import EncryptionProperties
    from ._models_py3 import ErrorAdditionalInfo
    from ._models_py3 import ErrorDetails
    from ._models_py3 import ErrorResponse
    from ._models_py3 import KeyValue
    from ._models_py3 import KeyValueListResult
    from ._models_py3 import KeyVaultProperties
    from ._models_py3 import LogSpecification
    from ._models_py3 import MetricDimension
    from ._models_py3 import MetricSpecification
    from ._models_py3 import NameAvailabilityStatus
    from ._models_py3 import OperationDefinition
    from ._models_py3 import OperationDefinitionDisplay
    from ._models_py3 import OperationDefinitionListResult
    from ._models_py3 import OperationProperties
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateEndpointConnectionListResult
    from ._models_py3 import PrivateEndpointConnectionReference
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkResourceListResult
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import RegenerateKeyParameters
    from ._models_py3 import Resource
    from ._models_py3 import ResourceIdentity
    from ._models_py3 import ServiceSpecification
    from ._models_py3 import Sku
    from ._models_py3 import SystemData
    from ._models_py3 import TrackedResource
    from ._models_py3 import UserIdentity
except (SyntaxError, ImportError):
    from ._models import ApiKey  # type: ignore
    from ._models import ApiKeyListResult  # type: ignore
    from ._models import CheckNameAvailabilityParameters  # type: ignore
    from ._models import ConfigurationStore  # type: ignore
    from ._models import ConfigurationStoreListResult  # type: ignore
    from ._models import ConfigurationStoreUpdateParameters  # type: ignore
    from ._models import EncryptionProperties  # type: ignore
    from ._models import ErrorAdditionalInfo  # type: ignore
    from ._models import ErrorDetails  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import KeyValue  # type: ignore
    from ._models import KeyValueListResult  # type: ignore
    from ._models import KeyVaultProperties  # type: ignore
    from ._models import LogSpecification  # type: ignore
    from ._models import MetricDimension  # type: ignore
    from ._models import MetricSpecification  # type: ignore
    from ._models import NameAvailabilityStatus  # type: ignore
    from ._models import OperationDefinition  # type: ignore
    from ._models import OperationDefinitionDisplay  # type: ignore
    from ._models import OperationDefinitionListResult  # type: ignore
    from ._models import OperationProperties  # type: ignore
    from ._models import PrivateEndpoint  # type: ignore
    from ._models import PrivateEndpointConnection  # type: ignore
    from ._models import PrivateEndpointConnectionListResult  # type: ignore
    from ._models import PrivateEndpointConnectionReference  # type: ignore
    from ._models import PrivateLinkResource  # type: ignore
    from ._models import PrivateLinkResourceListResult  # type: ignore
    from ._models import PrivateLinkServiceConnectionState  # type: ignore
    from ._models import RegenerateKeyParameters  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceIdentity  # type: ignore
    from ._models import ServiceSpecification  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import SystemData  # type: ignore
    from ._models import TrackedResource  # type: ignore
    from ._models import UserIdentity  # type: ignore

from ._app_configuration_management_client_enums import (
    ActionsRequired,
    ConfigurationResourceType,
    ConnectionStatus,
    CreatedByType,
    IdentityType,
    ProvisioningState,
    PublicNetworkAccess,
)

__all__ = [
    'ApiKey',
    'ApiKeyListResult',
    'CheckNameAvailabilityParameters',
    'ConfigurationStore',
    'ConfigurationStoreListResult',
    'ConfigurationStoreUpdateParameters',
    'EncryptionProperties',
    'ErrorAdditionalInfo',
    'ErrorDetails',
    'ErrorResponse',
    'KeyValue',
    'KeyValueListResult',
    'KeyVaultProperties',
    'LogSpecification',
    'MetricDimension',
    'MetricSpecification',
    'NameAvailabilityStatus',
    'OperationDefinition',
    'OperationDefinitionDisplay',
    'OperationDefinitionListResult',
    'OperationProperties',
    'PrivateEndpoint',
    'PrivateEndpointConnection',
    'PrivateEndpointConnectionListResult',
    'PrivateEndpointConnectionReference',
    'PrivateLinkResource',
    'PrivateLinkResourceListResult',
    'PrivateLinkServiceConnectionState',
    'RegenerateKeyParameters',
    'Resource',
    'ResourceIdentity',
    'ServiceSpecification',
    'Sku',
    'SystemData',
    'TrackedResource',
    'UserIdentity',
    'ActionsRequired',
    'ConfigurationResourceType',
    'ConnectionStatus',
    'CreatedByType',
    'IdentityType',
    'ProvisioningState',
    'PublicNetworkAccess',
]
