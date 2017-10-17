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


class TierType(Enum):

    consumption = "Consumption"
    commitment_100_au_hours = "Commitment_100AUHours"
    commitment_500_au_hours = "Commitment_500AUHours"
    commitment_1000_au_hours = "Commitment_1000AUHours"
    commitment_5000_au_hours = "Commitment_5000AUHours"
    commitment_10000_au_hours = "Commitment_10000AUHours"
    commitment_50000_au_hours = "Commitment_50000AUHours"
    commitment_100000_au_hours = "Commitment_100000AUHours"
    commitment_500000_au_hours = "Commitment_500000AUHours"


class FirewallState(Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class FirewallAllowAzureIpsState(Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class AADObjectType(Enum):

    user = "User"
    group = "Group"
    service_principal = "ServicePrincipal"


class DataLakeAnalyticsAccountStatus(Enum):

    failed = "Failed"
    creating = "Creating"
    running = "Running"
    succeeded = "Succeeded"
    patching = "Patching"
    suspending = "Suspending"
    resuming = "Resuming"
    deleting = "Deleting"
    deleted = "Deleted"
    undeleting = "Undeleting"
    canceled = "Canceled"


class DataLakeAnalyticsAccountState(Enum):

    active = "Active"
    suspended = "Suspended"


class SubscriptionState(Enum):

    registered = "Registered"
    suspended = "Suspended"
    deleted = "Deleted"
    unregistered = "Unregistered"
    warned = "Warned"


class OperationOrigin(Enum):

    user = "user"
    system = "system"
    usersystem = "user,system"
