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
    from ._models_py3 import CheckNameAvailabilityResult
    from ._models_py3 import CustomDomain
    from ._models_py3 import Encryption
    from ._models_py3 import EncryptionService
    from ._models_py3 import EncryptionServices
    from ._models_py3 import Endpoints
    from ._models_py3 import Resource
    from ._models_py3 import Sku
    from ._models_py3 import StorageAccount
    from ._models_py3 import StorageAccountCheckNameAvailabilityParameters
    from ._models_py3 import StorageAccountCreateParameters
    from ._models_py3 import StorageAccountKey
    from ._models_py3 import StorageAccountListKeysResult
    from ._models_py3 import StorageAccountRegenerateKeyParameters
    from ._models_py3 import StorageAccountUpdateParameters
    from ._models_py3 import Usage
    from ._models_py3 import UsageName
except (SyntaxError, ImportError):
    from ._models import CheckNameAvailabilityResult
    from ._models import CustomDomain
    from ._models import Encryption
    from ._models import EncryptionService
    from ._models import EncryptionServices
    from ._models import Endpoints
    from ._models import Resource
    from ._models import Sku
    from ._models import StorageAccount
    from ._models import StorageAccountCheckNameAvailabilityParameters
    from ._models import StorageAccountCreateParameters
    from ._models import StorageAccountKey
    from ._models import StorageAccountListKeysResult
    from ._models import StorageAccountRegenerateKeyParameters
    from ._models import StorageAccountUpdateParameters
    from ._models import Usage
    from ._models import UsageName
from ._paged_models import StorageAccountPaged
from ._paged_models import UsagePaged
from ._storage_management_client_enums import (
    Reason,
    SkuName,
    SkuTier,
    AccessTier,
    Kind,
    ProvisioningState,
    AccountStatus,
    KeyPermission,
    UsageUnit,
)

__all__ = [
    'CheckNameAvailabilityResult',
    'CustomDomain',
    'Encryption',
    'EncryptionService',
    'EncryptionServices',
    'Endpoints',
    'Resource',
    'Sku',
    'StorageAccount',
    'StorageAccountCheckNameAvailabilityParameters',
    'StorageAccountCreateParameters',
    'StorageAccountKey',
    'StorageAccountListKeysResult',
    'StorageAccountRegenerateKeyParameters',
    'StorageAccountUpdateParameters',
    'Usage',
    'UsageName',
    'StorageAccountPaged',
    'UsagePaged',
    'Reason',
    'SkuName',
    'SkuTier',
    'AccessTier',
    'Kind',
    'ProvisioningState',
    'AccountStatus',
    'KeyPermission',
    'UsageUnit',
]
