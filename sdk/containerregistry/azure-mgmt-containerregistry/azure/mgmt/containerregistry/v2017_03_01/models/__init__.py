# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import OperationDefinition
    from ._models_py3 import OperationDisplayDefinition
    from ._models_py3 import OperationListResult
    from ._models_py3 import RegenerateCredentialParameters
    from ._models_py3 import Registry
    from ._models_py3 import RegistryCreateParameters
    from ._models_py3 import RegistryListCredentialsResult
    from ._models_py3 import RegistryListResult
    from ._models_py3 import RegistryNameCheckRequest
    from ._models_py3 import RegistryNameStatus
    from ._models_py3 import RegistryPassword
    from ._models_py3 import RegistryUpdateParameters
    from ._models_py3 import Resource
    from ._models_py3 import Sku
    from ._models_py3 import StorageAccountParameters
    from ._models_py3 import StorageAccountProperties
except (SyntaxError, ImportError):
    from ._models import OperationDefinition  # type: ignore
    from ._models import OperationDisplayDefinition  # type: ignore
    from ._models import OperationListResult  # type: ignore
    from ._models import RegenerateCredentialParameters  # type: ignore
    from ._models import Registry  # type: ignore
    from ._models import RegistryCreateParameters  # type: ignore
    from ._models import RegistryListCredentialsResult  # type: ignore
    from ._models import RegistryListResult  # type: ignore
    from ._models import RegistryNameCheckRequest  # type: ignore
    from ._models import RegistryNameStatus  # type: ignore
    from ._models import RegistryPassword  # type: ignore
    from ._models import RegistryUpdateParameters  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import StorageAccountParameters  # type: ignore
    from ._models import StorageAccountProperties  # type: ignore

from ._container_registry_management_client_enums import (
    PasswordName,
    ProvisioningState,
    SkuTier,
)

__all__ = [
    'OperationDefinition',
    'OperationDisplayDefinition',
    'OperationListResult',
    'RegenerateCredentialParameters',
    'Registry',
    'RegistryCreateParameters',
    'RegistryListCredentialsResult',
    'RegistryListResult',
    'RegistryNameCheckRequest',
    'RegistryNameStatus',
    'RegistryPassword',
    'RegistryUpdateParameters',
    'Resource',
    'Sku',
    'StorageAccountParameters',
    'StorageAccountProperties',
    'PasswordName',
    'ProvisioningState',
    'SkuTier',
]
