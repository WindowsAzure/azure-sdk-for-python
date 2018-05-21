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
    from .check_name_availability_input_py3 import CheckNameAvailabilityInput
    from .check_name_availability_output_py3 import CheckNameAvailabilityOutput
    from .admin_key_result_py3 import AdminKeyResult
    from .query_key_py3 import QueryKey
    from .sku_py3 import Sku
    from .search_service_py3 import SearchService
    from .resource_py3 import Resource
    from .operation_display_py3 import OperationDisplay
    from .operation_py3 import Operation
    from .search_management_request_options_py3 import SearchManagementRequestOptions
except (SyntaxError, ImportError):
    from .check_name_availability_input import CheckNameAvailabilityInput
    from .check_name_availability_output import CheckNameAvailabilityOutput
    from .admin_key_result import AdminKeyResult
    from .query_key import QueryKey
    from .sku import Sku
    from .search_service import SearchService
    from .resource import Resource
    from .operation_display import OperationDisplay
    from .operation import Operation
    from .search_management_request_options import SearchManagementRequestOptions
from .operation_paged import OperationPaged
from .query_key_paged import QueryKeyPaged
from .search_service_paged import SearchServicePaged
from .search_management_client_enums import (
    UnavailableNameReason,
    SkuName,
    HostingMode,
    SearchServiceStatus,
    ProvisioningState,
    AdminKeyKind,
)

__all__ = [
    'CheckNameAvailabilityInput',
    'CheckNameAvailabilityOutput',
    'AdminKeyResult',
    'QueryKey',
    'Sku',
    'SearchService',
    'Resource',
    'OperationDisplay',
    'Operation',
    'SearchManagementRequestOptions',
    'OperationPaged',
    'QueryKeyPaged',
    'SearchServicePaged',
    'UnavailableNameReason',
    'SkuName',
    'HostingMode',
    'SearchServiceStatus',
    'ProvisioningState',
    'AdminKeyKind',
]
