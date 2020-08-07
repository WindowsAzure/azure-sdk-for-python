# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import CheckNameAvailabilityParameter
    from ._models_py3 import CheckNameAvailabilityResult
    from ._models_py3 import ConsumerGroupCreateOrUpdateParameters
    from ._models_py3 import ConsumerGroupListResult
    from ._models_py3 import ConsumerGroupResource
    from ._models_py3 import EventHubCreateOrUpdateParameters
    from ._models_py3 import EventHubListResult
    from ._models_py3 import EventHubResource
    from ._models_py3 import NamespaceCreateOrUpdateParameters
    from ._models_py3 import NamespaceListResult
    from ._models_py3 import NamespaceResource
    from ._models_py3 import NamespaceUpdateParameter
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationListResult
    from ._models_py3 import RegenerateKeysParameters
    from ._models_py3 import Resource
    from ._models_py3 import ResourceListKeys
    from ._models_py3 import SharedAccessAuthorizationRuleCreateOrUpdateParameters
    from ._models_py3 import SharedAccessAuthorizationRuleListResult
    from ._models_py3 import SharedAccessAuthorizationRuleResource
    from ._models_py3 import Sku
    from ._models_py3 import TrackedResource
except (SyntaxError, ImportError):
    from ._models import CheckNameAvailabilityParameter  # type: ignore
    from ._models import CheckNameAvailabilityResult  # type: ignore
    from ._models import ConsumerGroupCreateOrUpdateParameters  # type: ignore
    from ._models import ConsumerGroupListResult  # type: ignore
    from ._models import ConsumerGroupResource  # type: ignore
    from ._models import EventHubCreateOrUpdateParameters  # type: ignore
    from ._models import EventHubListResult  # type: ignore
    from ._models import EventHubResource  # type: ignore
    from ._models import NamespaceCreateOrUpdateParameters  # type: ignore
    from ._models import NamespaceListResult  # type: ignore
    from ._models import NamespaceResource  # type: ignore
    from ._models import NamespaceUpdateParameter  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import OperationListResult  # type: ignore
    from ._models import RegenerateKeysParameters  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceListKeys  # type: ignore
    from ._models import SharedAccessAuthorizationRuleCreateOrUpdateParameters  # type: ignore
    from ._models import SharedAccessAuthorizationRuleListResult  # type: ignore
    from ._models import SharedAccessAuthorizationRuleResource  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import TrackedResource  # type: ignore

from ._event_hub_management_client_enums import (
    AccessRights,
    EntityStatus,
    NamespaceState,
    Policykey,
    SkuName,
    SkuTier,
    UnavailableReason,
)

__all__ = [
    'CheckNameAvailabilityParameter',
    'CheckNameAvailabilityResult',
    'ConsumerGroupCreateOrUpdateParameters',
    'ConsumerGroupListResult',
    'ConsumerGroupResource',
    'EventHubCreateOrUpdateParameters',
    'EventHubListResult',
    'EventHubResource',
    'NamespaceCreateOrUpdateParameters',
    'NamespaceListResult',
    'NamespaceResource',
    'NamespaceUpdateParameter',
    'Operation',
    'OperationDisplay',
    'OperationListResult',
    'RegenerateKeysParameters',
    'Resource',
    'ResourceListKeys',
    'SharedAccessAuthorizationRuleCreateOrUpdateParameters',
    'SharedAccessAuthorizationRuleListResult',
    'SharedAccessAuthorizationRuleResource',
    'Sku',
    'TrackedResource',
    'AccessRights',
    'EntityStatus',
    'NamespaceState',
    'Policykey',
    'SkuName',
    'SkuTier',
    'UnavailableReason',
]
