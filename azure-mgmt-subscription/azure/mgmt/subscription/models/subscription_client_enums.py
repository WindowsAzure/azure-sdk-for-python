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


class OfferType(str, Enum):

    ms_azr_0017_p = "MS-AZR-0017P"
    ms_azr_0148_p = "MS-AZR-0148P"


class SubscriptionState(str, Enum):

    enabled = "Enabled"
    warned = "Warned"
    past_due = "PastDue"
    disabled = "Disabled"
    deleted = "Deleted"


class SpendingLimit(str, Enum):

    on = "On"
    off = "Off"
    current_period_off = "CurrentPeriodOff"
