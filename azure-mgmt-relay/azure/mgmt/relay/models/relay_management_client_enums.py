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


class Relaytype(str, Enum):

    net_tcp = "NetTcp"
    http = "Http"


class SkuTier(str, Enum):

    standard = "Standard"


class ProvisioningStateEnum(str, Enum):

    created = "Created"
    succeeded = "Succeeded"
    deleted = "Deleted"
    failed = "Failed"
    updating = "Updating"
    unknown = "Unknown"


class AccessRights(str, Enum):

    manage = "Manage"
    send = "Send"
    listen = "Listen"


class KeyType(str, Enum):

    primary_key = "PrimaryKey"
    secondary_key = "SecondaryKey"


class UnavailableReason(str, Enum):

    none = "None"
    invalid_name = "InvalidName"
    subscription_is_disabled = "SubscriptionIsDisabled"
    name_in_use = "NameInUse"
    name_in_lockdown = "NameInLockdown"
    too_many_namespace_in_current_subscription = "TooManyNamespaceInCurrentSubscription"
