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


class ReasonCode(str, Enum):

    quota_id = "QuotaId"
    not_available_for_subscription = "NotAvailableForSubscription"


class SkuName(str, Enum):

    standard_lrs = "Standard_LRS"
    standard_grs = "Standard_GRS"
    standard_ragrs = "Standard_RAGRS"
    standard_zrs = "Standard_ZRS"
    premium_lrs = "Premium_LRS"
    premium_zrs = "Premium_ZRS"
    standard_gzrs = "Standard_GZRS"
    standard_ragzrs = "Standard_RAGZRS"


class SkuTier(str, Enum):

    standard = "Standard"
    premium = "Premium"


class Kind(str, Enum):

    storage = "Storage"
    storage_v2 = "StorageV2"
    blob_storage = "BlobStorage"
    file_storage = "FileStorage"
    block_blob_storage = "BlockBlobStorage"


class Reason(str, Enum):

    account_name_invalid = "AccountNameInvalid"
    already_exists = "AlreadyExists"


class KeyType(str, Enum):

    service = "Service"
    account = "Account"


class KeySource(str, Enum):

    microsoft_storage = "Microsoft.Storage"
    microsoft_keyvault = "Microsoft.Keyvault"


class Action(str, Enum):

    allow = "Allow"


class State(str, Enum):

    provisioning = "provisioning"
    deprovisioning = "deprovisioning"
    succeeded = "succeeded"
    failed = "failed"
    network_source_deleted = "networkSourceDeleted"


class Bypass(str, Enum):

    none = "None"
    logging = "Logging"
    metrics = "Metrics"
    azure_services = "AzureServices"


class DefaultAction(str, Enum):

    allow = "Allow"
    deny = "Deny"


class DirectoryServiceOptions(str, Enum):

    none = "None"
    aadds = "AADDS"
    ad = "AD"


class AccessTier(str, Enum):

    hot = "Hot"
    cool = "Cool"


class LargeFileSharesState(str, Enum):

    disabled = "Disabled"
    enabled = "Enabled"


class RoutingChoice(str, Enum):

    microsoft_routing = "MicrosoftRouting"
    internet_routing = "InternetRouting"


class MinimumTlsVersion(str, Enum):

    tls1_0 = "TLS1_0"
    tls1_1 = "TLS1_1"
    tls1_2 = "TLS1_2"


class ExtendedLocationTypes(str, Enum):

    edge_zone = "EdgeZone"


class GeoReplicationStatus(str, Enum):

    live = "Live"
    bootstrap = "Bootstrap"
    unavailable = "Unavailable"


class BlobRestoreProgressStatus(str, Enum):

    in_progress = "InProgress"
    complete = "Complete"
    failed = "Failed"


class ProvisioningState(str, Enum):

    creating = "Creating"
    resolving_dns = "ResolvingDNS"
    succeeded = "Succeeded"


class AccountStatus(str, Enum):

    available = "available"
    unavailable = "unavailable"


class PrivateEndpointServiceConnectionStatus(str, Enum):

    pending = "Pending"
    approved = "Approved"
    rejected = "Rejected"


class PrivateEndpointConnectionProvisioningState(str, Enum):

    succeeded = "Succeeded"
    creating = "Creating"
    deleting = "Deleting"
    failed = "Failed"


class KeyPermission(str, Enum):

    read = "Read"
    full = "Full"


class UsageUnit(str, Enum):

    count = "Count"
    bytes = "Bytes"
    seconds = "Seconds"
    percent = "Percent"
    counts_per_second = "CountsPerSecond"
    bytes_per_second = "BytesPerSecond"


class Services(str, Enum):

    b = "b"
    q = "q"
    t = "t"
    f = "f"


class SignedResourceTypes(str, Enum):

    s = "s"
    c = "c"
    o = "o"


class Permissions(str, Enum):

    r = "r"
    d = "d"
    w = "w"
    l = "l"
    a = "a"
    c = "c"
    u = "u"
    p = "p"


class HttpProtocol(str, Enum):

    httpshttp = "https,http"
    https = "https"


class SignedResource(str, Enum):

    b = "b"
    c = "c"
    f = "f"
    s = "s"


class EncryptionScopeSource(str, Enum):

    microsoft_storage = "Microsoft.Storage"
    microsoft_key_vault = "Microsoft.KeyVault"


class EncryptionScopeState(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class CreatedByType(str, Enum):

    user = "User"
    application = "Application"
    managed_identity = "ManagedIdentity"
    key = "Key"


class PublicAccess(str, Enum):

    container = "Container"
    blob = "Blob"
    none = "None"


class LeaseStatus(str, Enum):

    locked = "Locked"
    unlocked = "Unlocked"


class LeaseState(str, Enum):

    available = "Available"
    leased = "Leased"
    expired = "Expired"
    breaking = "Breaking"
    broken = "Broken"


class LeaseDuration(str, Enum):

    infinite = "Infinite"
    fixed = "Fixed"


class ImmutabilityPolicyState(str, Enum):

    locked = "Locked"
    unlocked = "Unlocked"


class ImmutabilityPolicyUpdateType(str, Enum):

    put = "put"
    lock = "lock"
    extend = "extend"


class Name(str, Enum):

    access_time_tracking = "AccessTimeTracking"


class EnabledProtocols(str, Enum):

    smb = "SMB"
    nfs = "NFS"


class RootSquashType(str, Enum):

    no_root_squash = "NoRootSquash"
    root_squash = "RootSquash"
    all_squash = "AllSquash"


class ShareAccessTier(str, Enum):

    transaction_optimized = "TransactionOptimized"
    hot = "Hot"
    cool = "Cool"
    premium = "Premium"


class StorageAccountExpand(str, Enum):

    geo_replication_stats = "geoReplicationStats"
    blob_restore_status = "blobRestoreStatus"


class ListKeyExpand(str, Enum):

    kerb = "kerb"


class ListContainersInclude(str, Enum):

    deleted = "deleted"


class ListSharesExpand(str, Enum):

    deleted = "deleted"


class GetShareExpand(str, Enum):

    stats = "stats"
