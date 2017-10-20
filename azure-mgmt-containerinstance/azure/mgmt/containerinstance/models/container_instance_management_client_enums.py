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


class ContainerNetworkProtocol(Enum):

    tcp = "TCP"
    udp = "UDP"


class ContainerGroupRestartPolicy(Enum):

    always = "Always"
    on_failure = "OnFailure"
    never = "Never"


class ContainerGroupNetworkProtocol(Enum):

    tcp = "TCP"
    udp = "UDP"


class OperatingSystemTypes(Enum):

    windows = "Windows"
    linux = "Linux"


class ContainerInstanceOperationsOrigin(Enum):

    user = "User"
    system = "System"
