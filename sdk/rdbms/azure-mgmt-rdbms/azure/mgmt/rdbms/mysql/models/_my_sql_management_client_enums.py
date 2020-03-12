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

from enum import Enum


class ServerVersion(str, Enum):

    five_full_stop_six = "5.6"
    five_full_stop_seven = "5.7"
    eight_full_stop_zero = "8.0"


class SslEnforcementEnum(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class MinimalTlsVersionEnum(str, Enum):

    tls1_0 = "TLS1_0"
    tls1_1 = "TLS1_1"
    tls1_2 = "TLS1_2"
    tls_enforcement_disabled = "TLSEnforcementDisabled"


class PrivateLinkServiceConnectionStateStatus(str, Enum):

    approved = "Approved"
    pending = "Pending"
    rejected = "Rejected"
    disconnected = "Disconnected"


class PrivateLinkServiceConnectionStateActionsRequire(str, Enum):

    none = "None"


class PrivateEndpointProvisioningState(str, Enum):

    approving = "Approving"
    ready = "Ready"
    dropping = "Dropping"
    failed = "Failed"
    rejecting = "Rejecting"


class InfrastructureEncryption(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class ServerState(str, Enum):

    ready = "Ready"
    dropping = "Dropping"
    disabled = "Disabled"
    inaccessible = "Inaccessible"


class GeoRedundantBackup(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class StorageAutogrow(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class PublicNetworkAccessEnum(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class SkuTier(str, Enum):

    basic = "Basic"
    general_purpose = "GeneralPurpose"
    memory_optimized = "MemoryOptimized"


class IdentityType(str, Enum):

    system_assigned = "SystemAssigned"


class VirtualNetworkRuleState(str, Enum):

    initializing = "Initializing"
    in_progress = "InProgress"
    ready = "Ready"
    deleting = "Deleting"
    unknown = "Unknown"


class OperationOrigin(str, Enum):

    not_specified = "NotSpecified"
    user = "user"
    system = "system"


class ServerSecurityAlertPolicyState(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"
