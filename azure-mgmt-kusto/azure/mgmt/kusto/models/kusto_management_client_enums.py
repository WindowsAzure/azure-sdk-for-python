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
    updating = "Updating"


class ProvisioningState(str, Enum):

    running = "Running"
    creating = "Creating"
    deleting = "Deleting"
    succeeded = "Succeeded"
    failed = "Failed"


class AzureSkuName(str, Enum):

    d13_v2 = "D13_v2"
    d14_v2 = "D14_v2"
    l8 = "L8"
    l16 = "L16"
    d11_v2 = "D11_v2"
    d12_v2 = "D12_v2"
    l4 = "L4"


class AzureScaleType(str, Enum):

    automatic = "automatic"
    manual = "manual"
    none = "none"


class DataFormat(str, Enum):

    multijson = "MULTIJSON"
    json = "JSON"
    csv = "CSV"
    tsv = "TSV"
    scsv = "SCSV"
    sohsv = "SOHSV"
    psv = "PSV"
    txt = "TXT"
    raw = "RAW"
    singlejson = "SINGLEJSON"
    avro = "AVRO"


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


class Reason(str, Enum):

    invalid = "Invalid"
    already_exists = "AlreadyExists"
