# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from enum import Enum


class WorkflowProvisioningState(Enum):

    not_specified = "NotSpecified"
    moving = "Moving"
    succeeded = "Succeeded"


class WorkflowState(Enum):

    not_specified = "NotSpecified"
    enabled = "Enabled"
    disabled = "Disabled"
    deleted = "Deleted"
    suspended = "Suspended"


class SkuName(Enum):

    not_specified = "NotSpecified"
    free = "Free"
    shared = "Shared"
    basic = "Basic"
    standard = "Standard"
    premium = "Premium"


class ParameterType(Enum):

    not_specified = "NotSpecified"
    string = "String"
    secure_string = "SecureString"
    int_enum = "Int"
    float_enum = "Float"
    bool_enum = "Bool"
    array = "Array"
    object_enum = "Object"
    secure_object = "SecureObject"


class WorkflowTriggerProvisioningState(Enum):

    not_specified = "NotSpecified"
    creating = "Creating"
    succeeded = "Succeeded"
    updating = "Updating"


class WorkflowStatus(Enum):

    not_specified = "NotSpecified"
    paused = "Paused"
    running = "Running"
    waiting = "Waiting"
    succeeded = "Succeeded"
    skipped = "Skipped"
    suspended = "Suspended"
    cancelled = "Cancelled"
    failed = "Failed"
    faulted = "Faulted"
    timed_out = "TimedOut"
    aborted = "Aborted"


class RecurrenceFrequency(Enum):

    second = "Second"
    minute = "Minute"
    hour = "Hour"
    day = "Day"
    week = "Week"
    month = "Month"
    year = "Year"


class KeyType(Enum):

    not_specified = "NotSpecified"
    primary = "Primary"
    secondary = "Secondary"
