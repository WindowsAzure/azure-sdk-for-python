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


class SignalRSkuTier(str, Enum):

    free = "Free"
    basic = "Basic"
    premium = "Premium"


class ProvisioningState(str, Enum):

    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"
    creating = "Creating"
    updating = "Updating"
    deleting = "Deleting"
    moving = "Moving"


class KeyType(str, Enum):

    primary = "Primary"
    secondary = "Secondary"
