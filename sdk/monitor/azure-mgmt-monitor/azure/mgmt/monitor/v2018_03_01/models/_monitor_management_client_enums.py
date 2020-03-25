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


class ReceiverStatus(str, Enum):

    not_specified = "NotSpecified"
    enabled = "Enabled"
    disabled = "Disabled"


class Operator(str, Enum):

    equals = "Equals"
    not_equals = "NotEquals"
    greater_than = "GreaterThan"
    greater_than_or_equal = "GreaterThanOrEqual"
    less_than = "LessThan"
    less_than_or_equal = "LessThanOrEqual"


class DynamicThresholdOperator(str, Enum):

    greater_than = "GreaterThan"
    less_than = "LessThan"
    greater_or_less_than = "GreaterOrLessThan"


class DynamicThresholdSensitivity(str, Enum):

    low = "Low"
    medium = "Medium"
    high = "High"
