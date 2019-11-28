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


class ServerState(str, Enum):

    ready = "Ready"
    dropping = "Dropping"
    disabled = "Disabled"


class GeoRedundantBackup(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class StorageAutogrow(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class SkuTier(str, Enum):

    basic = "Basic"
    general_purpose = "GeneralPurpose"
    memory_optimized = "MemoryOptimized"


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
