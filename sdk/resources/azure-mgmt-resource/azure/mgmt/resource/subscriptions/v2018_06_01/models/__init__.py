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
    from ._models_py3 import CheckResourceNameResult
    from ._models_py3 import ErrorDefinition
    from ._models_py3 import ErrorResponse, ErrorResponseException
    from ._models_py3 import Location
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import ResourceName
    from ._models_py3 import Subscription
    from ._models_py3 import SubscriptionPolicies
    from ._models_py3 import TenantIdDescription
except (SyntaxError, ImportError):
    from ._models import CheckResourceNameResult
    from ._models import ErrorDefinition
    from ._models import ErrorResponse, ErrorResponseException
    from ._models import Location
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import ResourceName
    from ._models import Subscription
    from ._models import SubscriptionPolicies
    from ._models import TenantIdDescription
from ._paged_models import LocationPaged
from ._paged_models import OperationPaged
from ._paged_models import SubscriptionPaged
from ._paged_models import TenantIdDescriptionPaged
from ._subscription_client_enums import (
    SubscriptionState,
    SpendingLimit,
    ResourceNameStatus,
)

__all__ = [
    'CheckResourceNameResult',
    'ErrorDefinition',
    'ErrorResponse', 'ErrorResponseException',
    'Location',
    'Operation',
    'OperationDisplay',
    'ResourceName',
    'Subscription',
    'SubscriptionPolicies',
    'TenantIdDescription',
    'OperationPaged',
    'LocationPaged',
    'SubscriptionPaged',
    'TenantIdDescriptionPaged',
    'SubscriptionState',
    'SpendingLimit',
    'ResourceNameStatus',
]
