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
    from .resource_link_filter_py3 import ResourceLinkFilter
    from .resource_link_properties_py3 import ResourceLinkProperties
    from .resource_link_py3 import ResourceLink
    from .operation_display_py3 import OperationDisplay
    from .operation_py3 import Operation
except (SyntaxError, ImportError):
    from .resource_link_filter import ResourceLinkFilter
    from .resource_link_properties import ResourceLinkProperties
    from .resource_link import ResourceLink
    from .operation_display import OperationDisplay
    from .operation import Operation
from .operation_paged import OperationPaged
from .resource_link_paged import ResourceLinkPaged
from .management_link_client_enums import (
    Filter,
)

__all__ = [
    'ResourceLinkFilter',
    'ResourceLinkProperties',
    'ResourceLink',
    'OperationDisplay',
    'Operation',
    'OperationPaged',
    'ResourceLinkPaged',
    'Filter',
]
