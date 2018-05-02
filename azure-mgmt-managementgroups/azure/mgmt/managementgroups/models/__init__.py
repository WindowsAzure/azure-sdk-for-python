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
    from .error_details_py3 import ErrorDetails
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .operation_display_properties_py3 import OperationDisplayProperties
    from .operation_py3 import Operation
    from .check_name_availability_result_py3 import CheckNameAvailabilityResult
    from .management_group_info_py3 import ManagementGroupInfo
    from .parent_group_info_py3 import ParentGroupInfo
    from .management_group_details_py3 import ManagementGroupDetails
    from .management_group_child_info_py3 import ManagementGroupChildInfo
    from .management_group_py3 import ManagementGroup
    from .operation_results_py3 import OperationResults
    from .entity_parent_group_info_py3 import EntityParentGroupInfo
    from .entity_info_py3 import EntityInfo
    from .entity_hierarchy_item_py3 import EntityHierarchyItem
    from .patch_management_group_request_py3 import PatchManagementGroupRequest
    from .create_parent_group_info_py3 import CreateParentGroupInfo
    from .create_management_group_details_py3 import CreateManagementGroupDetails
    from .create_management_group_child_info_py3 import CreateManagementGroupChildInfo
    from .create_management_group_request_py3 import CreateManagementGroupRequest
    from .check_name_availability_request_py3 import CheckNameAvailabilityRequest
except (SyntaxError, ImportError):
    from .error_details import ErrorDetails
    from .error_response import ErrorResponse, ErrorResponseException
    from .operation_display_properties import OperationDisplayProperties
    from .operation import Operation
    from .check_name_availability_result import CheckNameAvailabilityResult
    from .management_group_info import ManagementGroupInfo
    from .parent_group_info import ParentGroupInfo
    from .management_group_details import ManagementGroupDetails
    from .management_group_child_info import ManagementGroupChildInfo
    from .management_group import ManagementGroup
    from .operation_results import OperationResults
    from .entity_parent_group_info import EntityParentGroupInfo
    from .entity_info import EntityInfo
    from .entity_hierarchy_item import EntityHierarchyItem
    from .patch_management_group_request import PatchManagementGroupRequest
    from .create_parent_group_info import CreateParentGroupInfo
    from .create_management_group_details import CreateManagementGroupDetails
    from .create_management_group_child_info import CreateManagementGroupChildInfo
    from .create_management_group_request import CreateManagementGroupRequest
    from .check_name_availability_request import CheckNameAvailabilityRequest
from .management_group_info_paged import ManagementGroupInfoPaged
from .operation_paged import OperationPaged
from .entity_info_paged import EntityInfoPaged
from .management_groups_api_enums import (
    Reason,
    Type,
)

__all__ = [
    'ErrorDetails',
    'ErrorResponse', 'ErrorResponseException',
    'OperationDisplayProperties',
    'Operation',
    'CheckNameAvailabilityResult',
    'ManagementGroupInfo',
    'ParentGroupInfo',
    'ManagementGroupDetails',
    'ManagementGroupChildInfo',
    'ManagementGroup',
    'OperationResults',
    'EntityParentGroupInfo',
    'EntityInfo',
    'EntityHierarchyItem',
    'PatchManagementGroupRequest',
    'CreateParentGroupInfo',
    'CreateManagementGroupDetails',
    'CreateManagementGroupChildInfo',
    'CreateManagementGroupRequest',
    'CheckNameAvailabilityRequest',
    'ManagementGroupInfoPaged',
    'OperationPaged',
    'EntityInfoPaged',
    'Reason',
    'Type',
]
