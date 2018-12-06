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


class ImportMode(str, Enum):

    no_force = "NoForce"
    force = "Force"


class SkuName(str, Enum):

    classic = "Classic"
    basic = "Basic"
    standard = "Standard"
    premium = "Premium"


class SkuTier(str, Enum):

    classic = "Classic"
    basic = "Basic"
    standard = "Standard"
    premium = "Premium"


class ProvisioningState(str, Enum):

    creating = "Creating"
    updating = "Updating"
    deleting = "Deleting"
    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"


class DefaultAction(str, Enum):

    allow = "Allow"
    deny = "Deny"


class PasswordName(str, Enum):

    password = "password"
    password2 = "password2"


class RegistryUsageUnit(str, Enum):

    count = "Count"
    bytes = "Bytes"


class PolicyStatus(str, Enum):

    enabled = "enabled"
    disabled = "disabled"


class TrustPolicyType(str, Enum):

    notary = "Notary"


class WebhookStatus(str, Enum):

    enabled = "enabled"
    disabled = "disabled"


class WebhookAction(str, Enum):

    push = "push"
    delete = "delete"
    quarantine = "quarantine"
    chart_push = "chart_push"
    chart_delete = "chart_delete"
