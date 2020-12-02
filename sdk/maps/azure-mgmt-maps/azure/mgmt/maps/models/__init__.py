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
    from ._models_py3 import AzureEntityResource
    from ._models_py3 import Creator
    from ._models_py3 import CreatorCreateParameters
    from ._models_py3 import CreatorProperties
    from ._models_py3 import CreatorUpdateParameters
    from ._models_py3 import ErrorAdditionalInfo
    from ._models_py3 import ErrorDetail
    from ._models_py3 import ErrorResponse, ErrorResponseException
    from ._models_py3 import MapsAccount
    from ._models_py3 import MapsAccountCreateParameters
    from ._models_py3 import MapsAccountKeys
    from ._models_py3 import MapsAccountProperties
    from ._models_py3 import MapsAccountUpdateParameters
    from ._models_py3 import MapsKeySpecification
    from ._models_py3 import MapsOperationsValueItem
    from ._models_py3 import MapsOperationsValueItemDisplay
    from ._models_py3 import PrivateAtlas
    from ._models_py3 import PrivateAtlasCreateParameters
    from ._models_py3 import PrivateAtlasProperties
    from ._models_py3 import PrivateAtlasUpdateParameters
    from ._models_py3 import ProxyResource
    from ._models_py3 import Resource
    from ._models_py3 import Sku
    from ._models_py3 import SystemData
    from ._models_py3 import TrackedResource
except (SyntaxError, ImportError):
    from ._models import AzureEntityResource
    from ._models import Creator
    from ._models import CreatorCreateParameters
    from ._models import CreatorProperties
    from ._models import CreatorUpdateParameters
    from ._models import ErrorAdditionalInfo
    from ._models import ErrorDetail
    from ._models import ErrorResponse, ErrorResponseException
    from ._models import MapsAccount
    from ._models import MapsAccountCreateParameters
    from ._models import MapsAccountKeys
    from ._models import MapsAccountProperties
    from ._models import MapsAccountUpdateParameters
    from ._models import MapsKeySpecification
    from ._models import MapsOperationsValueItem
    from ._models import MapsOperationsValueItemDisplay
    from ._models import PrivateAtlas
    from ._models import PrivateAtlasCreateParameters
    from ._models import PrivateAtlasProperties
    from ._models import PrivateAtlasUpdateParameters
    from ._models import ProxyResource
    from ._models import Resource
    from ._models import Sku
    from ._models import SystemData
    from ._models import TrackedResource
from ._paged_models import CreatorPaged
from ._paged_models import MapsAccountPaged
from ._paged_models import MapsOperationsValueItemPaged
from ._paged_models import PrivateAtlasPaged
from ._maps_management_client_enums import (
    CreatedByType,
    KeyType,
)

__all__ = [
    'AzureEntityResource',
    'Creator',
    'CreatorCreateParameters',
    'CreatorProperties',
    'CreatorUpdateParameters',
    'ErrorAdditionalInfo',
    'ErrorDetail',
    'ErrorResponse', 'ErrorResponseException',
    'MapsAccount',
    'MapsAccountCreateParameters',
    'MapsAccountKeys',
    'MapsAccountProperties',
    'MapsAccountUpdateParameters',
    'MapsKeySpecification',
    'MapsOperationsValueItem',
    'MapsOperationsValueItemDisplay',
    'PrivateAtlas',
    'PrivateAtlasCreateParameters',
    'PrivateAtlasProperties',
    'PrivateAtlasUpdateParameters',
    'ProxyResource',
    'Resource',
    'Sku',
    'SystemData',
    'TrackedResource',
    'MapsAccountPaged',
    'MapsOperationsValueItemPaged',
    'PrivateAtlasPaged',
    'CreatorPaged',
    'CreatedByType',
    'KeyType',
]
