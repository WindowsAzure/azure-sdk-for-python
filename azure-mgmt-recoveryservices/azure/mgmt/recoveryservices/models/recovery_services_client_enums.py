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


class AuthType(str, Enum):

    invalid = "Invalid"
    acs = "ACS"
    aad = "AAD"
    access_control_service = "AccessControlService"
    azure_active_directory = "AzureActiveDirectory"


class SkuName(str, Enum):

    standard = "Standard"
    rs0 = "RS0"


class VaultUpgradeState(str, Enum):

    unknown = "Unknown"
    in_progress = "InProgress"
    upgraded = "Upgraded"
    failed = "Failed"


class TriggerType(str, Enum):

    user_triggered = "UserTriggered"
    forced_upgrade = "ForcedUpgrade"


class UsagesUnit(str, Enum):

    count = "Count"
    bytes = "Bytes"
    seconds = "Seconds"
    percent = "Percent"
    count_per_second = "CountPerSecond"
    bytes_per_second = "BytesPerSecond"
