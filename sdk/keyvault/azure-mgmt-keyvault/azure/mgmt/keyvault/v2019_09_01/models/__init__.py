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
    from ._models_py3 import AccessPolicyEntry
    from ._models_py3 import Attributes
    from ._models_py3 import CheckNameAvailabilityResult
    from ._models_py3 import DeletedVault
    from ._models_py3 import DeletedVaultProperties
    from ._models_py3 import IPRule
    from ._models_py3 import Key
    from ._models_py3 import KeyAttributes
    from ._models_py3 import KeyCreateParameters
    from ._models_py3 import KeyProperties
    from ._models_py3 import LogSpecification
    from ._models_py3 import NetworkRuleSet
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import Permissions
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateEndpointConnectionItem
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkResourceListResult
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import Resource
    from ._models_py3 import ServiceSpecification
    from ._models_py3 import Sku
    from ._models_py3 import Vault
    from ._models_py3 import VaultAccessPolicyParameters
    from ._models_py3 import VaultAccessPolicyProperties
    from ._models_py3 import VaultCheckNameAvailabilityParameters
    from ._models_py3 import VaultCreateOrUpdateParameters
    from ._models_py3 import VaultPatchParameters
    from ._models_py3 import VaultPatchProperties
    from ._models_py3 import VaultProperties
    from ._models_py3 import VirtualNetworkRule
except (SyntaxError, ImportError):
    from ._models import AccessPolicyEntry
    from ._models import Attributes
    from ._models import CheckNameAvailabilityResult
    from ._models import DeletedVault
    from ._models import DeletedVaultProperties
    from ._models import IPRule
    from ._models import Key
    from ._models import KeyAttributes
    from ._models import KeyCreateParameters
    from ._models import KeyProperties
    from ._models import LogSpecification
    from ._models import NetworkRuleSet
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import Permissions
    from ._models import PrivateEndpoint
    from ._models import PrivateEndpointConnection
    from ._models import PrivateEndpointConnectionItem
    from ._models import PrivateLinkResource
    from ._models import PrivateLinkResourceListResult
    from ._models import PrivateLinkServiceConnectionState
    from ._models import Resource
    from ._models import ServiceSpecification
    from ._models import Sku
    from ._models import Vault
    from ._models import VaultAccessPolicyParameters
    from ._models import VaultAccessPolicyProperties
    from ._models import VaultCheckNameAvailabilityParameters
    from ._models import VaultCreateOrUpdateParameters
    from ._models import VaultPatchParameters
    from ._models import VaultPatchProperties
    from ._models import VaultProperties
    from ._models import VirtualNetworkRule
from ._paged_models import DeletedVaultPaged
from ._paged_models import KeyPaged
from ._paged_models import OperationPaged
from ._paged_models import ResourcePaged
from ._paged_models import VaultPaged
from ._key_vault_management_client_enums import (
    SkuName,
    KeyPermissions,
    SecretPermissions,
    CertificatePermissions,
    StoragePermissions,
    CreateMode,
    NetworkRuleBypassOptions,
    NetworkRuleAction,
    PrivateEndpointServiceConnectionStatus,
    PrivateEndpointConnectionProvisioningState,
    Reason,
    DeletionRecoveryLevel,
    JsonWebKeyType,
    JsonWebKeyOperation,
    JsonWebKeyCurveName,
    AccessPolicyUpdateKind,
)

__all__ = [
    'AccessPolicyEntry',
    'Attributes',
    'CheckNameAvailabilityResult',
    'DeletedVault',
    'DeletedVaultProperties',
    'IPRule',
    'Key',
    'KeyAttributes',
    'KeyCreateParameters',
    'KeyProperties',
    'LogSpecification',
    'NetworkRuleSet',
    'Operation',
    'OperationDisplay',
    'Permissions',
    'PrivateEndpoint',
    'PrivateEndpointConnection',
    'PrivateEndpointConnectionItem',
    'PrivateLinkResource',
    'PrivateLinkResourceListResult',
    'PrivateLinkServiceConnectionState',
    'Resource',
    'ServiceSpecification',
    'Sku',
    'Vault',
    'VaultAccessPolicyParameters',
    'VaultAccessPolicyProperties',
    'VaultCheckNameAvailabilityParameters',
    'VaultCreateOrUpdateParameters',
    'VaultPatchParameters',
    'VaultPatchProperties',
    'VaultProperties',
    'VirtualNetworkRule',
    'VaultPaged',
    'DeletedVaultPaged',
    'ResourcePaged',
    'OperationPaged',
    'KeyPaged',
    'SkuName',
    'KeyPermissions',
    'SecretPermissions',
    'CertificatePermissions',
    'StoragePermissions',
    'CreateMode',
    'NetworkRuleBypassOptions',
    'NetworkRuleAction',
    'PrivateEndpointServiceConnectionStatus',
    'PrivateEndpointConnectionProvisioningState',
    'Reason',
    'DeletionRecoveryLevel',
    'JsonWebKeyType',
    'JsonWebKeyOperation',
    'JsonWebKeyCurveName',
    'AccessPolicyUpdateKind',
]
