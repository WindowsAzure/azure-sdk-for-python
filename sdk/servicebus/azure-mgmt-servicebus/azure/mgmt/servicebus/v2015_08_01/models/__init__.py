# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import CheckNameAvailability
    from ._models_py3 import CheckNameAvailabilityResult
    from ._models_py3 import MessageCountDetails
    from ._models_py3 import NamespaceCreateOrUpdateParameters
    from ._models_py3 import NamespaceListResult
    from ._models_py3 import NamespaceResource
    from ._models_py3 import NamespaceUpdateParameters
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationListResult
    from ._models_py3 import QueueCreateOrUpdateParameters
    from ._models_py3 import QueueListResult
    from ._models_py3 import QueueResource
    from ._models_py3 import RegenerateKeysParameters
    from ._models_py3 import Resource
    from ._models_py3 import ResourceListKeys
    from ._models_py3 import SharedAccessAuthorizationRuleCreateOrUpdateParameters
    from ._models_py3 import SharedAccessAuthorizationRuleListResult
    from ._models_py3 import SharedAccessAuthorizationRuleResource
    from ._models_py3 import Sku
    from ._models_py3 import SubscriptionCreateOrUpdateParameters
    from ._models_py3 import SubscriptionListResult
    from ._models_py3 import SubscriptionResource
    from ._models_py3 import TopicCreateOrUpdateParameters
    from ._models_py3 import TopicListResult
    from ._models_py3 import TopicResource
    from ._models_py3 import TrackedResource
except (SyntaxError, ImportError):
    from ._models import CheckNameAvailability  # type: ignore
    from ._models import CheckNameAvailabilityResult  # type: ignore
    from ._models import MessageCountDetails  # type: ignore
    from ._models import NamespaceCreateOrUpdateParameters  # type: ignore
    from ._models import NamespaceListResult  # type: ignore
    from ._models import NamespaceResource  # type: ignore
    from ._models import NamespaceUpdateParameters  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import OperationListResult  # type: ignore
    from ._models import QueueCreateOrUpdateParameters  # type: ignore
    from ._models import QueueListResult  # type: ignore
    from ._models import QueueResource  # type: ignore
    from ._models import RegenerateKeysParameters  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceListKeys  # type: ignore
    from ._models import SharedAccessAuthorizationRuleCreateOrUpdateParameters  # type: ignore
    from ._models import SharedAccessAuthorizationRuleListResult  # type: ignore
    from ._models import SharedAccessAuthorizationRuleResource  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import SubscriptionCreateOrUpdateParameters  # type: ignore
    from ._models import SubscriptionListResult  # type: ignore
    from ._models import SubscriptionResource  # type: ignore
    from ._models import TopicCreateOrUpdateParameters  # type: ignore
    from ._models import TopicListResult  # type: ignore
    from ._models import TopicResource  # type: ignore
    from ._models import TrackedResource  # type: ignore

from ._service_bus_management_client_enums import (
    AccessRights,
    EntityAvailabilityStatus,
    EntityStatus,
    NamespaceState,
    Policykey,
    SkuName,
    SkuTier,
    UnavailableReason,
)

__all__ = [
    'CheckNameAvailability',
    'CheckNameAvailabilityResult',
    'MessageCountDetails',
    'NamespaceCreateOrUpdateParameters',
    'NamespaceListResult',
    'NamespaceResource',
    'NamespaceUpdateParameters',
    'Operation',
    'OperationDisplay',
    'OperationListResult',
    'QueueCreateOrUpdateParameters',
    'QueueListResult',
    'QueueResource',
    'RegenerateKeysParameters',
    'Resource',
    'ResourceListKeys',
    'SharedAccessAuthorizationRuleCreateOrUpdateParameters',
    'SharedAccessAuthorizationRuleListResult',
    'SharedAccessAuthorizationRuleResource',
    'Sku',
    'SubscriptionCreateOrUpdateParameters',
    'SubscriptionListResult',
    'SubscriptionResource',
    'TopicCreateOrUpdateParameters',
    'TopicListResult',
    'TopicResource',
    'TrackedResource',
    'AccessRights',
    'EntityAvailabilityStatus',
    'EntityStatus',
    'NamespaceState',
    'Policykey',
    'SkuName',
    'SkuTier',
    'UnavailableReason',
]
