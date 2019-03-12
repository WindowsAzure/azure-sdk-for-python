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


class State(str, Enum):

    creating = "Creating"
    unavailable = "Unavailable"
    running = "Running"
    deleting = "Deleting"
    deleted = "Deleted"
    stopping = "Stopping"
    stopped = "Stopped"
    starting = "Starting"


class ProvisioningState(str, Enum):

    running = "Running"
    creating = "Creating"
    deleting = "Deleting"
    succeeded = "Succeeded"
    failed = "Failed"


class AzureSkuName(str, Enum):

    kc8 = "KC8"
    kc16 = "KC16"
    ks8 = "KS8"
    ks16 = "KS16"
    d13_v2 = "D13_v2"
    d14_v2 = "D14_v2"
    l8 = "L8"
    l16 = "L16"


class AzureScaleType(str, Enum):

    automatic = "automatic"
    manual = "manual"
    none = "none"


class DataFormat(str, Enum):

    multijson = "MULTIJSON"
    json = "JSON"
    csv = "CSV"


class DatabasePrincipalRole(str, Enum):

    admin = "Admin"
    ingestor = "Ingestor"
    monitor = "Monitor"
    user = "User"
    unrestricted_viewers = "UnrestrictedViewers"
    viewer = "Viewer"


class DatabasePrincipalType(str, Enum):

    app = "App"
    group = "Group"
    user = "User"
