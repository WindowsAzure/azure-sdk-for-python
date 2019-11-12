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


class HanaHardwareTypeNamesEnum(str, Enum):

    cisco_ucs = "Cisco_UCS"
    hpe = "HPE"


class HanaInstanceSizeNamesEnum(str, Enum):

    s72m = "S72m"
    s144m = "S144m"
    s72 = "S72"
    s144 = "S144"
    s192 = "S192"
    s192m = "S192m"
    s192xm = "S192xm"
    s96 = "S96"
    s112 = "S112"
    s224m = "S224m"
    s224o = "S224o"
    s224om = "S224om"
    s224oo = "S224oo"
    s224oom = "S224oom"
    s224ooo = "S224ooo"
    s224oxm = "S224oxm"
    s224oxxm = "S224oxxm"
    s384 = "S384"
    s384m = "S384m"
    s384xm = "S384xm"
    s384xxm = "S384xxm"
    s576m = "S576m"
    s576xm = "S576xm"
    s768 = "S768"
    s768m = "S768m"
    s768xm = "S768xm"
    s960m = "S960m"


class HanaInstancePowerStateEnum(str, Enum):

    starting = "starting"
    started = "started"
    stopping = "stopping"
    stopped = "stopped"
    restarting = "restarting"
    unknown = "unknown"


class HanaProvisioningStatesEnum(str, Enum):

    accepted = "Accepted"
    creating = "Creating"
    updating = "Updating"
    failed = "Failed"
    succeeded = "Succeeded"
    deleting = "Deleting"
    migrating = "Migrating"
