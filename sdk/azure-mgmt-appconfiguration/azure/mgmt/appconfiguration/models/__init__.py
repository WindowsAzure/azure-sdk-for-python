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
    from .configuration_store_py3 import ConfigurationStore
    from .configuration_store_update_parameters_py3 import ConfigurationStoreUpdateParameters
    from .check_name_availability_parameters_py3 import CheckNameAvailabilityParameters
    from .name_availability_status_py3 import NameAvailabilityStatus
    from .api_key_py3 import ApiKey
    from .regenerate_key_parameters_py3 import RegenerateKeyParameters
    from .operation_definition_display_py3 import OperationDefinitionDisplay
    from .operation_definition_py3 import OperationDefinition
    from .error_py3 import Error, ErrorException
    from .resource_py3 import Resource
except (SyntaxError, ImportError):
    from .configuration_store import ConfigurationStore
    from .configuration_store_update_parameters import ConfigurationStoreUpdateParameters
    from .check_name_availability_parameters import CheckNameAvailabilityParameters
    from .name_availability_status import NameAvailabilityStatus
    from .api_key import ApiKey
    from .regenerate_key_parameters import RegenerateKeyParameters
    from .operation_definition_display import OperationDefinitionDisplay
    from .operation_definition import OperationDefinition
    from .error import Error, ErrorException
    from .resource import Resource
from .configuration_store_paged import ConfigurationStorePaged
from .api_key_paged import ApiKeyPaged
from .operation_definition_paged import OperationDefinitionPaged
from .app_configuration_management_client_enums import (
    ProvisioningState,
)

__all__ = [
    'ConfigurationStore',
    'ConfigurationStoreUpdateParameters',
    'CheckNameAvailabilityParameters',
    'NameAvailabilityStatus',
    'ApiKey',
    'RegenerateKeyParameters',
    'OperationDefinitionDisplay',
    'OperationDefinition',
    'Error', 'ErrorException',
    'Resource',
    'ConfigurationStorePaged',
    'ApiKeyPaged',
    'OperationDefinitionPaged',
    'ProvisioningState',
]
