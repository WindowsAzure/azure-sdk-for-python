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
    moving = "Moving"


class AzureSkuName(str, Enum):

    standard_ds13_v21_tb_ps = "Standard_DS13_v2+1TB_PS"
    standard_ds13_v22_tb_ps = "Standard_DS13_v2+2TB_PS"
    standard_ds14_v23_tb_ps = "Standard_DS14_v2+3TB_PS"
    standard_ds14_v24_tb_ps = "Standard_DS14_v2+4TB_PS"
    standard_d13_v2 = "Standard_D13_v2"
    standard_d14_v2 = "Standard_D14_v2"
    standard_l8s = "Standard_L8s"
    standard_l16s = "Standard_L16s"
    standard_d11_v2 = "Standard_D11_v2"
    standard_d12_v2 = "Standard_D12_v2"
    standard_l4s = "Standard_L4s"
    dev_no_sla_standard_d11_v2 = "Dev(No SLA)_Standard_D11_v2"


class AzureSkuTier(str, Enum):

    basic = "Basic"
    standard = "Standard"


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
