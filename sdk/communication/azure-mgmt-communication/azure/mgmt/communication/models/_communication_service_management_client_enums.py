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


class AggregationType(str, Enum):

    average = "Average"
    minimum = "Minimum"
    maximum = "Maximum"
    total = "Total"
    count = "Count"


class Status(str, Enum):

    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"
    creating = "Creating"
    deleting = "Deleting"
    moving = "Moving"


class ProvisioningState(str, Enum):

    unknown = "Unknown"
    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"
    running = "Running"
    creating = "Creating"
    updating = "Updating"
    deleting = "Deleting"
    moving = "Moving"


class KeyType(str, Enum):

    primary = "Primary"
    secondary = "Secondary"
