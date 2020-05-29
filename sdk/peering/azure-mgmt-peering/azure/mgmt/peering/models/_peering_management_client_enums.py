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


class Tier(str, Enum):

    basic = "Basic"
    premium = "Premium"


class Family(str, Enum):

    direct = "Direct"
    exchange = "Exchange"


class Size(str, Enum):

    free = "Free"
    metered = "Metered"
    unlimited = "Unlimited"


class Kind(str, Enum):

    direct = "Direct"
    exchange = "Exchange"


class SessionAddressProvider(str, Enum):

    microsoft = "Microsoft"
    peer = "Peer"


class ConnectionState(str, Enum):

    none = "None"
    pending_approval = "PendingApproval"
    approved = "Approved"
    provisioning_started = "ProvisioningStarted"
    provisioning_failed = "ProvisioningFailed"
    provisioning_completed = "ProvisioningCompleted"
    validating = "Validating"
    active = "Active"


class SessionStateV4(str, Enum):

    none = "None"
    idle = "Idle"
    connect = "Connect"
    active = "Active"
    open_sent = "OpenSent"
    open_confirm = "OpenConfirm"
    open_received = "OpenReceived"
    established = "Established"
    pending_add = "PendingAdd"
    pending_update = "PendingUpdate"
    pending_remove = "PendingRemove"


class SessionStateV6(str, Enum):

    none = "None"
    idle = "Idle"
    connect = "Connect"
    active = "Active"
    open_sent = "OpenSent"
    open_confirm = "OpenConfirm"
    open_received = "OpenReceived"
    established = "Established"
    pending_add = "PendingAdd"
    pending_update = "PendingUpdate"
    pending_remove = "PendingRemove"


class DirectPeeringType(str, Enum):

    edge = "Edge"
    transit = "Transit"
    cdn = "Cdn"
    internal = "Internal"
    ix = "Ix"
    ix_rs = "IxRs"


class ProvisioningState(str, Enum):

    succeeded = "Succeeded"
    updating = "Updating"
    deleting = "Deleting"
    failed = "Failed"


class Role(str, Enum):

    noc = "Noc"
    policy = "Policy"
    technical = "Technical"
    service = "Service"
    escalation = "Escalation"
    other = "Other"


class ValidationState(str, Enum):

    none = "None"
    pending = "Pending"
    approved = "Approved"
    failed = "Failed"


class PrefixValidationState(str, Enum):

    none = "None"
    invalid = "Invalid"
    verified = "Verified"
    failed = "Failed"
    pending = "Pending"
    warning = "Warning"
    unknown = "Unknown"


class LearnedType(str, Enum):

    none = "None"
    via_service_provider = "ViaServiceProvider"
    via_session = "ViaSession"
