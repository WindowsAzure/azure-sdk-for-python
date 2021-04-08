# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import Change
    from ._models_py3 import ChangeList
    from ._models_py3 import ChangeProperties
    from ._models_py3 import ErrorAdditionalInfo
    from ._models_py3 import ErrorDetail
    from ._models_py3 import ErrorResponse
    from ._models_py3 import PropertyChange
    from ._models_py3 import ProxyResource
    from ._models_py3 import Resource
    from ._models_py3 import ResourceProviderOperationDefinition
    from ._models_py3 import ResourceProviderOperationDisplay
    from ._models_py3 import ResourceProviderOperationList
except (SyntaxError, ImportError):
    from ._models import Change  # type: ignore
    from ._models import ChangeList  # type: ignore
    from ._models import ChangeProperties  # type: ignore
    from ._models import ErrorAdditionalInfo  # type: ignore
    from ._models import ErrorDetail  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import PropertyChange  # type: ignore
    from ._models import ProxyResource  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceProviderOperationDefinition  # type: ignore
    from ._models import ResourceProviderOperationDisplay  # type: ignore
    from ._models import ResourceProviderOperationList  # type: ignore

from ._azure_change_analysis_management_client_enums import (
    ChangeCategory,
    ChangeType,
    Level,
)

__all__ = [
    'Change',
    'ChangeList',
    'ChangeProperties',
    'ErrorAdditionalInfo',
    'ErrorDetail',
    'ErrorResponse',
    'PropertyChange',
    'ProxyResource',
    'Resource',
    'ResourceProviderOperationDefinition',
    'ResourceProviderOperationDisplay',
    'ResourceProviderOperationList',
    'ChangeCategory',
    'ChangeType',
    'Level',
]
