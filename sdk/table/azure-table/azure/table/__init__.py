# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from azure.table._entity import Entity, EntityProperty, EdmType
from azure.table._generated.models import QueryOptions, TableServiceStats
from azure.table._shared.table_shared_access_signature import generate_table_sas, \
    generate_account_shared_access_signature
from azure.table._table_client import TableClient
from azure.table._table_service_client import TableServiceClient

from ._models import (
    AccessPolicy,
    Metrics,
    RetentionPolicy, TableAnalyticsLogging, TableSasPermissions, CorsRule, UpdateMode,
)
from ._shared.models import (
    LocationMode,
    ResourceTypes,
    AccountSasPermissions,
    StorageErrorCode
)
from ._shared.policies import ExponentialRetry, LinearRetry
from ._version import VERSION

__version__ = VERSION

__all__ = [
    'TableClient',
    'TableServiceClient',
    'ExponentialRetry',
    'LinearRetry',
    'LocationMode',
    'ResourceTypes',
    'AccountSasPermissions',
    'StorageErrorCode',
    'TableServiceStats',
    'TableSasPermissions',
    'AccessPolicy',
    'TableAnalyticsLogging',
    'Metrics',
    'generate_account_shared_access_signature',
    'CorsRule',
    'UpdateMode',
    'Entity',
    'EntityProperty',
    'EdmType',
    'RetentionPolicy',
    'generate_table_sas'
]
