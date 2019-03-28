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
    from .role_assignment_filter_py3 import RoleAssignmentFilter
    from .role_assignment_py3 import RoleAssignment
    from .role_assignment_create_parameters_py3 import RoleAssignmentCreateParameters
except (SyntaxError, ImportError):
    from .role_assignment_filter import RoleAssignmentFilter
    from .role_assignment import RoleAssignment
    from .role_assignment_create_parameters import RoleAssignmentCreateParameters
from .role_assignment_paged import RoleAssignmentPaged
from .authorization_management_client_enums import (
    PrincipalType,
)

__all__ = [
    'RoleAssignmentFilter',
    'RoleAssignment',
    'RoleAssignmentCreateParameters',
    'RoleAssignmentPaged',
    'PrincipalType',
]
