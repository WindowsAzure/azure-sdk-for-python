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


class ApplicationType(Enum):

    web = "web"
    other = "other"


class FlowType(Enum):

    bluefield = "Bluefield"


class RequestSource(Enum):

    rest = "rest"


class WebTestKind(Enum):

    ping = "ping"
    multistep = "multistep"
