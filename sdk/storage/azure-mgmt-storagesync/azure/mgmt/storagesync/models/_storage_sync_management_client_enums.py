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


class Reason(str, Enum):

    registered = "Registered"
    unregistered = "Unregistered"
    warned = "Warned"
    suspended = "Suspended"
    deleted = "Deleted"


class IncomingTrafficPolicy(str, Enum):

    allow_all_traffic = "AllowAllTraffic"
    allow_virtual_networks_only = "AllowVirtualNetworksOnly"


class PrivateEndpointServiceConnectionStatus(str, Enum):

    pending = "Pending"
    approved = "Approved"
    rejected = "Rejected"


class PrivateEndpointConnectionProvisioningState(str, Enum):

    succeeded = "Succeeded"
    creating = "Creating"
    deleting = "Deleting"
    failed = "Failed"


class ChangeDetectionMode(str, Enum):

    default = "Default"
    recursive = "Recursive"


class FeatureStatus(str, Enum):

    on = "on"
    off = "off"


class InitialDownloadPolicy(str, Enum):

    namespace_only = "NamespaceOnly"
    namespace_then_modified_files = "NamespaceThenModifiedFiles"
    avoid_tiered_files = "AvoidTieredFiles"


class LocalCacheMode(str, Enum):

    download_new_and_modified_files = "DownloadNewAndModifiedFiles"
    update_locally_cached_files = "UpdateLocallyCachedFiles"


class ServerEndpointHealthState(str, Enum):

    unavailable = "Unavailable"
    healthy = "Healthy"
    error = "Error"


class ServerEndpointSyncActivityState(str, Enum):

    upload = "Upload"
    download = "Download"
    upload_and_download = "UploadAndDownload"


class ServerEndpointSyncMode(str, Enum):

    regular = "Regular"
    namespace_download = "NamespaceDownload"
    initial_upload = "InitialUpload"
    snapshot_upload = "SnapshotUpload"
    initial_full_download = "InitialFullDownload"


class ServerEndpointOfflineDataTransferState(str, Enum):

    in_progress = "InProgress"
    stopping = "Stopping"
    not_running = "NotRunning"
    complete = "Complete"


class RegisteredServerAgentVersionStatus(str, Enum):

    ok = "Ok"
    near_expiry = "NearExpiry"
    expired = "Expired"
    blocked = "Blocked"


class WorkflowStatus(str, Enum):

    active = "active"
    expired = "expired"
    succeeded = "succeeded"
    aborted = "aborted"
    failed = "failed"


class OperationDirection(str, Enum):

    do = "do"
    undo = "undo"
    cancel = "cancel"


class NameAvailabilityReason(str, Enum):

    invalid = "Invalid"
    already_exists = "AlreadyExists"


class ProgressType(str, Enum):

    none = "none"
    initialize = "initialize"
    download = "download"
    upload = "upload"
    recall = "recall"
