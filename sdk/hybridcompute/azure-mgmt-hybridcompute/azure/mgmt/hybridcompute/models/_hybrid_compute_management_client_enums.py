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


class StatusTypes(str, Enum):

    connected = "Connected"
    disconnected = "Disconnected"
    error = "Error"


class StatusLevelTypes(str, Enum):

    info = "Info"
    warning = "Warning"
    error = "Error"


class PublicNetworkAccessType(str, Enum):

    enabled = "Enabled"  #: Allows Azure Arc agents to communicate with Azure Arc services over both public (internet) and private endpoints.
    disabled = "Disabled"  #: Does not allow Azure Arc agents to communicate with Azure Arc services over public (internet) endpoints. The agents must use the private link.


class InstanceViewTypes(str, Enum):

    instance_view = "instanceView"
