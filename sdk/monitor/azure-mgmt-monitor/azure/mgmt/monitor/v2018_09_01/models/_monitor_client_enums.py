# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum

class ReceiverStatus(str, Enum):
    """Indicates the status of the receiver. Receivers that are not Enabled will not receive any
    communications.
    """

    not_specified = "NotSpecified"
    enabled = "Enabled"
    disabled = "Disabled"

class ResultType(str, Enum):

    data = "Data"
    metadata = "Metadata"

class Sensitivity(str, Enum):
    """The sensitivity of the baseline.
    """

    low = "Low"
    medium = "Medium"
    high = "High"
