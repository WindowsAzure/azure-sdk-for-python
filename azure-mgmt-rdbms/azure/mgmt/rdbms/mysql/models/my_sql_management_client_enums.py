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


class ServerVersion(Enum):

    five_full_stop_six = "5.6"
    five_full_stop_seven = "5.7"


class SslEnforcementEnum(Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class ServerState(Enum):

    ready = "Ready"
    dropping = "Dropping"
    disabled = "Disabled"


class SkuTier(Enum):

    basic = "Basic"
    standard = "Standard"


class OperationOrigin(Enum):

    not_specified = "NotSpecified"
    user = "user"
    system = "system"
