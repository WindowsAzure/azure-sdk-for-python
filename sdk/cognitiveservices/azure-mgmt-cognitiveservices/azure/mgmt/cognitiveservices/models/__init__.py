# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import CheckDomainAvailabilityParameter
    from ._models_py3 import CheckDomainAvailabilityResult
    from ._models_py3 import CheckSkuAvailabilityParameter
    from ._models_py3 import CheckSkuAvailabilityResult
    from ._models_py3 import CheckSkuAvailabilityResultList
    from ._models_py3 import CognitiveServicesAccount
    from ._models_py3 import CognitiveServicesAccountApiProperties
    from ._models_py3 import CognitiveServicesAccountEnumerateSkusResult
    from ._models_py3 import CognitiveServicesAccountKeys
    from ._models_py3 import CognitiveServicesAccountListResult
    from ._models_py3 import CognitiveServicesAccountProperties
    from ._models_py3 import CognitiveServicesResourceAndSku
    from ._models_py3 import Encryption
    from ._models_py3 import Error
    from ._models_py3 import ErrorBody
    from ._models_py3 import Identity
    from ._models_py3 import IpRule
    from ._models_py3 import KeyVaultProperties
    from ._models_py3 import MetricName
    from ._models_py3 import NetworkRuleSet
    from ._models_py3 import OperationDisplayInfo
    from ._models_py3 import OperationEntity
    from ._models_py3 import OperationEntityListResult
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateEndpointConnectionListResult
    from ._models_py3 import PrivateEndpointConnectionProperties
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkResourceListResult
    from ._models_py3 import PrivateLinkResourceProperties
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import RegenerateKeyParameters
    from ._models_py3 import Resource
    from ._models_py3 import ResourceSku
    from ._models_py3 import ResourceSkuRestrictionInfo
    from ._models_py3 import ResourceSkuRestrictions
    from ._models_py3 import ResourceSkusResult
    from ._models_py3 import Sku
    from ._models_py3 import SkuCapability
    from ._models_py3 import Usage
    from ._models_py3 import UsagesResult
    from ._models_py3 import UserAssignedIdentity
    from ._models_py3 import UserOwnedStorage
    from ._models_py3 import VirtualNetworkRule
except (SyntaxError, ImportError):
    from ._models import CheckDomainAvailabilityParameter  # type: ignore
    from ._models import CheckDomainAvailabilityResult  # type: ignore
    from ._models import CheckSkuAvailabilityParameter  # type: ignore
    from ._models import CheckSkuAvailabilityResult  # type: ignore
    from ._models import CheckSkuAvailabilityResultList  # type: ignore
    from ._models import CognitiveServicesAccount  # type: ignore
    from ._models import CognitiveServicesAccountApiProperties  # type: ignore
    from ._models import CognitiveServicesAccountEnumerateSkusResult  # type: ignore
    from ._models import CognitiveServicesAccountKeys  # type: ignore
    from ._models import CognitiveServicesAccountListResult  # type: ignore
    from ._models import CognitiveServicesAccountProperties  # type: ignore
    from ._models import CognitiveServicesResourceAndSku  # type: ignore
    from ._models import Encryption  # type: ignore
    from ._models import Error  # type: ignore
    from ._models import ErrorBody  # type: ignore
    from ._models import Identity  # type: ignore
    from ._models import IpRule  # type: ignore
    from ._models import KeyVaultProperties  # type: ignore
    from ._models import MetricName  # type: ignore
    from ._models import NetworkRuleSet  # type: ignore
    from ._models import OperationDisplayInfo  # type: ignore
    from ._models import OperationEntity  # type: ignore
    from ._models import OperationEntityListResult  # type: ignore
    from ._models import PrivateEndpoint  # type: ignore
    from ._models import PrivateEndpointConnection  # type: ignore
    from ._models import PrivateEndpointConnectionListResult  # type: ignore
    from ._models import PrivateEndpointConnectionProperties  # type: ignore
    from ._models import PrivateLinkResource  # type: ignore
    from ._models import PrivateLinkResourceListResult  # type: ignore
    from ._models import PrivateLinkResourceProperties  # type: ignore
    from ._models import PrivateLinkServiceConnectionState  # type: ignore
    from ._models import RegenerateKeyParameters  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceSku  # type: ignore
    from ._models import ResourceSkuRestrictionInfo  # type: ignore
    from ._models import ResourceSkuRestrictions  # type: ignore
    from ._models import ResourceSkusResult  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import SkuCapability  # type: ignore
    from ._models import Usage  # type: ignore
    from ._models import UsagesResult  # type: ignore
    from ._models import UserAssignedIdentity  # type: ignore
    from ._models import UserOwnedStorage  # type: ignore
    from ._models import VirtualNetworkRule  # type: ignore

from ._cognitive_services_management_client_enums import (
    IdentityType,
    KeyName,
    KeySource,
    NetworkRuleAction,
    PrivateEndpointServiceConnectionStatus,
    ProvisioningState,
    PublicNetworkAccess,
    QuotaUsageStatus,
    ResourceSkuRestrictionsReasonCode,
    ResourceSkuRestrictionsType,
    SkuTier,
    UnitType,
)

__all__ = [
    'CheckDomainAvailabilityParameter',
    'CheckDomainAvailabilityResult',
    'CheckSkuAvailabilityParameter',
    'CheckSkuAvailabilityResult',
    'CheckSkuAvailabilityResultList',
    'CognitiveServicesAccount',
    'CognitiveServicesAccountApiProperties',
    'CognitiveServicesAccountEnumerateSkusResult',
    'CognitiveServicesAccountKeys',
    'CognitiveServicesAccountListResult',
    'CognitiveServicesAccountProperties',
    'CognitiveServicesResourceAndSku',
    'Encryption',
    'Error',
    'ErrorBody',
    'Identity',
    'IpRule',
    'KeyVaultProperties',
    'MetricName',
    'NetworkRuleSet',
    'OperationDisplayInfo',
    'OperationEntity',
    'OperationEntityListResult',
    'PrivateEndpoint',
    'PrivateEndpointConnection',
    'PrivateEndpointConnectionListResult',
    'PrivateEndpointConnectionProperties',
    'PrivateLinkResource',
    'PrivateLinkResourceListResult',
    'PrivateLinkResourceProperties',
    'PrivateLinkServiceConnectionState',
    'RegenerateKeyParameters',
    'Resource',
    'ResourceSku',
    'ResourceSkuRestrictionInfo',
    'ResourceSkuRestrictions',
    'ResourceSkusResult',
    'Sku',
    'SkuCapability',
    'Usage',
    'UsagesResult',
    'UserAssignedIdentity',
    'UserOwnedStorage',
    'VirtualNetworkRule',
    'IdentityType',
    'KeyName',
    'KeySource',
    'NetworkRuleAction',
    'PrivateEndpointServiceConnectionStatus',
    'ProvisioningState',
    'PublicNetworkAccess',
    'QuotaUsageStatus',
    'ResourceSkuRestrictionsReasonCode',
    'ResourceSkuRestrictionsType',
    'SkuTier',
    'UnitType',
]
