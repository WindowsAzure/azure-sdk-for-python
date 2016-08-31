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


class OSType(Enum):

    linux = "linux"
    windows = "windows"
    unmapped = "unmapped"


class CertificateState(Enum):

    active = "active"
    deleting = "deleting"
    deletefailed = "deletefailed"


class CertificateFormat(Enum):

    pfx = "pfx"
    cer = "cer"
    unmapped = "unmapped"


class ComputeNodeFillType(Enum):

    spread = "spread"
    pack = "pack"
    unmapped = "unmapped"


class CertificateStoreLocation(Enum):

    currentuser = "currentuser"
    localmachine = "localmachine"
    unmapped = "unmapped"


class CertificateVisibility(Enum):

    starttask = "starttask"
    task = "task"
    remoteuser = "remoteuser"
    unmapped = "unmapped"


class PoolLifetimeOption(Enum):

    jobschedule = "jobschedule"
    job = "job"
    unmapped = "unmapped"


class JobScheduleState(Enum):

    active = "active"
    completed = "completed"
    disabled = "disabled"
    terminating = "terminating"
    deleting = "deleting"


class SchedulingErrorCategory(Enum):

    usererror = "usererror"
    servererror = "servererror"
    unmapped = "unmapped"


class JobState(Enum):

    active = "active"
    disabling = "disabling"
    disabled = "disabled"
    enabling = "enabling"
    terminating = "terminating"
    completed = "completed"
    deleting = "deleting"


class JobPreparationTaskState(Enum):

    running = "running"
    completed = "completed"


class JobReleaseTaskState(Enum):

    running = "running"
    completed = "completed"


class PoolState(Enum):

    active = "active"
    deleting = "deleting"
    upgrading = "upgrading"


class AllocationState(Enum):

    steady = "steady"
    resizing = "resizing"
    stopping = "stopping"


class TaskState(Enum):

    active = "active"
    preparing = "preparing"
    running = "running"
    completed = "completed"


class TaskAddStatus(Enum):

    success = "success"
    clienterror = "clienterror"
    servererror = "servererror"
    unmapped = "unmapped"


class StartTaskState(Enum):

    running = "running"
    completed = "completed"


class ComputeNodeState(Enum):

    idle = "idle"
    rebooting = "rebooting"
    reimaging = "reimaging"
    running = "running"
    unusable = "unusable"
    creating = "creating"
    starting = "starting"
    waitingforstarttask = "waitingforstarttask"
    starttaskfailed = "starttaskfailed"
    unknown = "unknown"
    leavingpool = "leavingpool"
    offline = "offline"


class SchedulingState(Enum):

    enabled = "enabled"
    disabled = "disabled"


class DisableJobOption(Enum):

    requeue = "requeue"
    terminate = "terminate"
    wait = "wait"


class ComputeNodeDeallocationOption(Enum):

    requeue = "requeue"
    terminate = "terminate"
    taskcompletion = "taskcompletion"
    retaineddata = "retaineddata"


class ComputeNodeRebootOption(Enum):

    requeue = "requeue"
    terminate = "terminate"
    taskcompletion = "taskcompletion"
    retaineddata = "retaineddata"


class ComputeNodeReimageOption(Enum):

    requeue = "requeue"
    terminate = "terminate"
    taskcompletion = "taskcompletion"
    retaineddata = "retaineddata"


class DisableComputeNodeSchedulingOption(Enum):

    requeue = "requeue"
    terminate = "terminate"
    taskcompletion = "taskcompletion"
