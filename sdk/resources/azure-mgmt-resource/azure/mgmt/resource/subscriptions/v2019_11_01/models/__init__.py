# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import Location
    from ._models_py3 import LocationListResult
    from ._models_py3 import LocationMetadata
    from ._models_py3 import ManagedByTenant
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationListResult
    from ._models_py3 import PairedRegion
    from ._models_py3 import Subscription
    from ._models_py3 import SubscriptionListResult
    from ._models_py3 import SubscriptionPolicies
    from ._models_py3 import TenantIdDescription
    from ._models_py3 import TenantListResult
except (SyntaxError, ImportError):
    from ._models import Location  # type: ignore
    from ._models import LocationListResult  # type: ignore
    from ._models import LocationMetadata  # type: ignore
    from ._models import ManagedByTenant  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import OperationListResult  # type: ignore
    from ._models import PairedRegion  # type: ignore
    from ._models import Subscription  # type: ignore
    from ._models import SubscriptionListResult  # type: ignore
    from ._models import SubscriptionPolicies  # type: ignore
    from ._models import TenantIdDescription  # type: ignore
    from ._models import TenantListResult  # type: ignore

from ._subscription_client_enums import (
    RegionCategory,
    RegionType,
    SpendingLimit,
    SubscriptionState,
    TenantCategory,
)

__all__ = [
    'Location',
    'LocationListResult',
    'LocationMetadata',
    'ManagedByTenant',
    'Operation',
    'OperationDisplay',
    'OperationListResult',
    'PairedRegion',
    'Subscription',
    'SubscriptionListResult',
    'SubscriptionPolicies',
    'TenantIdDescription',
    'TenantListResult',
    'RegionCategory',
    'RegionType',
    'SpendingLimit',
    'SubscriptionState',
    'TenantCategory',
]
