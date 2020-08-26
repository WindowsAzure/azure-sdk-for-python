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


class ProvisioningState(str, Enum):

    unknown = "Unknown"
    updating = "Updating"
    creating = "Creating"
    deleting = "Deleting"
    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"


class EncryptionStatus(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class PrivateEndpointServiceConnectionStatus(str, Enum):

    pending = "Pending"
    approved = "Approved"
    rejected = "Rejected"
    disconnected = "Disconnected"
    timeout = "Timeout"


class PrivateEndpointConnectionProvisioningState(str, Enum):

    succeeded = "Succeeded"
    creating = "Creating"
    deleting = "Deleting"
    failed = "Failed"


class UsageUnit(str, Enum):

    count = "Count"


class QuotaUnit(str, Enum):

    count = "Count"


class Status(str, Enum):

    undefined = "Undefined"
    success = "Success"
    failure = "Failure"
    invalid_quota_below_cluster_minimum = "InvalidQuotaBelowClusterMinimum"
    invalid_quota_exceeds_subscription_limit = "InvalidQuotaExceedsSubscriptionLimit"
    invalid_vm_family_name = "InvalidVMFamilyName"
    operation_not_supported_for_sku = "OperationNotSupportedForSku"
    operation_not_enabled_for_region = "OperationNotEnabledForRegion"


class ResourceIdentityType(str, Enum):

    system_assigned = "SystemAssigned"
    user_assigned = "UserAssigned"
    system_assigned_user_assigned = "SystemAssigned, UserAssigned"
    none = "None"


class VmPriority(str, Enum):

    dedicated = "Dedicated"
    low_priority = "LowPriority"


class RemoteLoginPortPublicAccess(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"
    not_specified = "NotSpecified"


class AllocationState(str, Enum):

    steady = "Steady"
    resizing = "Resizing"


class ApplicationSharingPolicy(str, Enum):

    personal = "Personal"
    shared = "Shared"


class SshPublicAccess(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class ComputeInstanceState(str, Enum):

    creating = "Creating"
    create_failed = "CreateFailed"
    deleting = "Deleting"
    running = "Running"
    restarting = "Restarting"
    restart_failed = "RestartFailed"
    job_running = "JobRunning"
    setting_up = "SettingUp"
    starting = "Starting"
    start_failed = "StartFailed"
    stop_failed = "StopFailed"
    stopped = "Stopped"
    stopping = "Stopping"
    user_setting_up = "UserSettingUp"
    unknown = "Unknown"
    unusable = "Unusable"


class NodeState(str, Enum):

    idle = "idle"
    running = "running"
    preparing = "preparing"
    unusable = "unusable"
    leaving = "leaving"
    preempted = "preempted"


class ComputeType(str, Enum):

    aks = "AKS"
    aml_compute = "AmlCompute"
    compute_instance = "ComputeInstance"
    data_factory = "DataFactory"
    virtual_machine = "VirtualMachine"
    hd_insight = "HDInsight"
    databricks = "Databricks"
    data_lake_analytics = "DataLakeAnalytics"


class ReasonCode(str, Enum):

    not_specified = "NotSpecified"
    not_available_for_region = "NotAvailableForRegion"
    not_available_for_subscription = "NotAvailableForSubscription"


class UnderlyingResourceAction(str, Enum):

    delete = "Delete"
    detach = "Detach"
