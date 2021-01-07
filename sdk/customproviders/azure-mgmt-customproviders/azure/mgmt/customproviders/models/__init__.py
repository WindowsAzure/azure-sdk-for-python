# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import Association
    from ._models_py3 import AssociationsList
    from ._models_py3 import CustomRPActionRouteDefinition
    from ._models_py3 import CustomRPManifest
    from ._models_py3 import CustomRPResourceTypeRouteDefinition
    from ._models_py3 import CustomRPRouteDefinition
    from ._models_py3 import CustomRPValidations
    from ._models_py3 import ErrorDefinition
    from ._models_py3 import ErrorResponse
    from ._models_py3 import ListByCustomRPManifest
    from ._models_py3 import Resource
    from ._models_py3 import ResourceProviderOperation
    from ._models_py3 import ResourceProviderOperationDisplay
    from ._models_py3 import ResourceProviderOperationList
    from ._models_py3 import ResourceProvidersUpdate
except (SyntaxError, ImportError):
    from ._models import Association  # type: ignore
    from ._models import AssociationsList  # type: ignore
    from ._models import CustomRPActionRouteDefinition  # type: ignore
    from ._models import CustomRPManifest  # type: ignore
    from ._models import CustomRPResourceTypeRouteDefinition  # type: ignore
    from ._models import CustomRPRouteDefinition  # type: ignore
    from ._models import CustomRPValidations  # type: ignore
    from ._models import ErrorDefinition  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import ListByCustomRPManifest  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceProviderOperation  # type: ignore
    from ._models import ResourceProviderOperationDisplay  # type: ignore
    from ._models import ResourceProviderOperationList  # type: ignore
    from ._models import ResourceProvidersUpdate  # type: ignore

from ._customproviders_enums import (
    ActionRouting,
    ProvisioningState,
    ResourceTypeRouting,
    ValidationType,
)

__all__ = [
    'Association',
    'AssociationsList',
    'CustomRPActionRouteDefinition',
    'CustomRPManifest',
    'CustomRPResourceTypeRouteDefinition',
    'CustomRPRouteDefinition',
    'CustomRPValidations',
    'ErrorDefinition',
    'ErrorResponse',
    'ListByCustomRPManifest',
    'Resource',
    'ResourceProviderOperation',
    'ResourceProviderOperationDisplay',
    'ResourceProviderOperationList',
    'ResourceProvidersUpdate',
    'ActionRouting',
    'ProvisioningState',
    'ResourceTypeRouting',
    'ValidationType',
]
