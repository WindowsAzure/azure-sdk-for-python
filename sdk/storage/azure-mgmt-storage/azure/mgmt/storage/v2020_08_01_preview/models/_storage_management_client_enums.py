# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class AccessTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Required for storage accounts where kind = BlobStorage. The access tier used for billing.
    """

    HOT = "Hot"
    COOL = "Cool"

class AccountStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the status indicating whether the primary location of the storage account is available or
    unavailable.
    """

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"

class BlobRestoreProgressStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of blob restore progress. Possible values are: - InProgress: Indicates that blob
    restore is ongoing. - Complete: Indicates that blob restore has been completed successfully. -
    Failed: Indicates that blob restore is failed.
    """

    IN_PROGRESS = "InProgress"
    COMPLETE = "Complete"
    FAILED = "Failed"

class Bypass(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are
    any combination of Logging|Metrics|AzureServices (For example, "Logging, Metrics"), or None to
    bypass none of those traffics.
    """

    NONE = "None"
    LOGGING = "Logging"
    METRICS = "Metrics"
    AZURE_SERVICES = "AzureServices"

class CorsRuleAllowedMethodsItem(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DELETE = "DELETE"
    GET = "GET"
    HEAD = "HEAD"
    MERGE = "MERGE"
    POST = "POST"
    OPTIONS = "OPTIONS"
    PUT = "PUT"

class DefaultAction(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the default action of allow or deny when no other rules match.
    """

    ALLOW = "Allow"
    DENY = "Deny"

class DirectoryServiceOptions(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates the directory service used.
    """

    NONE = "None"
    AADDS = "AADDS"
    AD = "AD"

class EnabledProtocols(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The authentication protocol that is used for the file share. Can only be specified when
    creating a share.
    """

    SMB = "SMB"
    NFS = "NFS"

class EncryptionScopeSource(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provider for the encryption scope. Possible values (case-insensitive):  Microsoft.Storage,
    Microsoft.KeyVault.
    """

    MICROSOFT_STORAGE = "Microsoft.Storage"
    MICROSOFT_KEY_VAULT = "Microsoft.KeyVault"

class EncryptionScopeState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The state of the encryption scope. Possible values (case-insensitive):  Enabled, Disabled.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class ExtendedLocationTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of extendedLocation.
    """

    EDGE_ZONE = "EdgeZone"

class GeoReplicationStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the secondary location. Possible values are: - Live: Indicates that the secondary
    location is active and operational. - Bootstrap: Indicates initial synchronization from the
    primary location to the secondary location is in progress.This typically occurs when
    replication is first enabled. - Unavailable: Indicates that the secondary location is
    temporarily unavailable.
    """

    LIVE = "Live"
    BOOTSTRAP = "Bootstrap"
    UNAVAILABLE = "Unavailable"

class HttpProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The protocol permitted for a request made with the account SAS.
    """

    HTTPS_HTTP = "https,http"
    HTTPS = "https"

class ImmutabilityPolicyState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The ImmutabilityPolicy state of a blob container, possible values include: Locked and Unlocked.
    """

    LOCKED = "Locked"
    UNLOCKED = "Unlocked"

class ImmutabilityPolicyUpdateType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The ImmutabilityPolicy update type of a blob container, possible values include: put, lock and
    extend.
    """

    PUT = "put"
    LOCK = "lock"
    EXTEND = "extend"

class KeyPermission(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Permissions for the key -- read-only or full permissions.
    """

    READ = "Read"
    FULL = "Full"

class KeySource(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The encryption keySource (provider). Possible values (case-insensitive):  Microsoft.Storage,
    Microsoft.Keyvault
    """

    MICROSOFT_STORAGE = "Microsoft.Storage"
    MICROSOFT_KEYVAULT = "Microsoft.Keyvault"

class KeyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Encryption key type to be used for the encryption service. 'Account' key type implies that an
    account-scoped encryption key will be used. 'Service' key type implies that a default service
    key is used.
    """

    SERVICE = "Service"
    ACCOUNT = "Account"

class Kind(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates the type of storage account.
    """

    STORAGE = "Storage"
    STORAGE_V2 = "StorageV2"
    BLOB_STORAGE = "BlobStorage"
    FILE_STORAGE = "FileStorage"
    BLOCK_BLOB_STORAGE = "BlockBlobStorage"

class LargeFileSharesState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Allow large file shares if sets to Enabled. It cannot be disabled once it is enabled.
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class LeaseContainerRequestAction(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the lease action. Can be one of the available actions.
    """

    ACQUIRE = "Acquire"
    RENEW = "Renew"
    CHANGE = "Change"
    RELEASE = "Release"
    BREAK_ENUM = "Break"

class LeaseDuration(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies whether the lease on a container is of infinite or fixed duration, only when the
    container is leased.
    """

    INFINITE = "Infinite"
    FIXED = "Fixed"

class LeaseState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Lease state of the container.
    """

    AVAILABLE = "Available"
    LEASED = "Leased"
    EXPIRED = "Expired"
    BREAKING = "Breaking"
    BROKEN = "Broken"

class LeaseStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The lease status of the container.
    """

    LOCKED = "Locked"
    UNLOCKED = "Unlocked"

class ListContainersInclude(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DELETED = "deleted"

class ManagementPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "default"

class MinimumTlsVersion(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Set the minimum TLS version to be permitted on requests to storage. The default interpretation
    is TLS 1.0 for this property.
    """

    TLS1_0 = "TLS1_0"
    TLS1_1 = "TLS1_1"
    TLS1_2 = "TLS1_2"

class Name(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Name of the policy. The valid value is AccessTimeTracking. This field is currently read only
    """

    ACCESS_TIME_TRACKING = "AccessTimeTracking"

class Permissions(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The signed permissions for the account SAS. Possible values include: Read (r), Write (w),
    Delete (d), List (l), Add (a), Create (c), Update (u) and Process (p).
    """

    R = "r"
    D = "d"
    W = "w"
    L = "l"
    A = "a"
    C = "c"
    U = "u"
    P = "p"

class PrivateEndpointConnectionProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current provisioning state.
    """

    SUCCEEDED = "Succeeded"
    CREATING = "Creating"
    DELETING = "Deleting"
    FAILED = "Failed"

class PrivateEndpointServiceConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The private endpoint connection status.
    """

    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the status of the storage account at the time the operation was called.
    """

    CREATING = "Creating"
    RESOLVING_DNS = "ResolvingDNS"
    SUCCEEDED = "Succeeded"

class PublicAccess(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies whether data in the container may be accessed publicly and the level of access.
    """

    CONTAINER = "Container"
    BLOB = "Blob"
    NONE = "None"

class Reason(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the reason that a storage account name could not be used. The Reason element is only
    returned if NameAvailable is false.
    """

    ACCOUNT_NAME_INVALID = "AccountNameInvalid"
    ALREADY_EXISTS = "AlreadyExists"

class ReasonCode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The reason for the restriction. As of now this can be "QuotaId" or
    "NotAvailableForSubscription". Quota Id is set when the SKU has requiredQuotas parameter as the
    subscription does not belong to that quota. The "NotAvailableForSubscription" is related to
    capacity at DC.
    """

    QUOTA_ID = "QuotaId"
    NOT_AVAILABLE_FOR_SUBSCRIPTION = "NotAvailableForSubscription"

class RootSquashType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The property is for NFS share only. The default is NoRootSquash.
    """

    NO_ROOT_SQUASH = "NoRootSquash"
    ROOT_SQUASH = "RootSquash"
    ALL_SQUASH = "AllSquash"

class RoutingChoice(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Routing Choice defines the kind of network routing opted by the user.
    """

    MICROSOFT_ROUTING = "MicrosoftRouting"
    INTERNET_ROUTING = "InternetRouting"

class RuleType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The valid value is Lifecycle
    """

    LIFECYCLE = "Lifecycle"

class Services(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The signed services accessible with the account SAS. Possible values include: Blob (b), Queue
    (q), Table (t), File (f).
    """

    B = "b"
    Q = "q"
    T = "t"
    F = "f"

class ShareAccessTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Access tier for specific share. GpV2 account can choose between TransactionOptimized (default),
    Hot, and Cool. FileStorage account can choose Premium.
    """

    TRANSACTION_OPTIMIZED = "TransactionOptimized"
    HOT = "Hot"
    COOL = "Cool"
    PREMIUM = "Premium"

class SignedResource(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The signed services accessible with the service SAS. Possible values include: Blob (b),
    Container (c), File (f), Share (s).
    """

    B = "b"
    C = "c"
    F = "f"
    S = "s"

class SignedResourceTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The signed resource types that are accessible with the account SAS. Service (s): Access to
    service-level APIs; Container (c): Access to container-level APIs; Object (o): Access to
    object-level APIs for blobs, queue messages, table entities, and files.
    """

    S = "s"
    C = "c"
    O = "o"

class SkuName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The SKU name. Required for account creation; optional for update. Note that in older versions,
    SKU name was called accountType.
    """

    STANDARD_LRS = "Standard_LRS"
    STANDARD_GRS = "Standard_GRS"
    STANDARD_RAGRS = "Standard_RAGRS"
    STANDARD_ZRS = "Standard_ZRS"
    PREMIUM_LRS = "Premium_LRS"
    PREMIUM_ZRS = "Premium_ZRS"
    STANDARD_GZRS = "Standard_GZRS"
    STANDARD_RAGZRS = "Standard_RAGZRS"

class SkuTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The SKU tier. This is based on the SKU name.
    """

    STANDARD = "Standard"
    PREMIUM = "Premium"

class State(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the state of virtual network rule.
    """

    PROVISIONING = "provisioning"
    DEPROVISIONING = "deprovisioning"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    NETWORK_SOURCE_DELETED = "networkSourceDeleted"

class StorageAccountExpand(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    GEO_REPLICATION_STATS = "geoReplicationStats"
    BLOB_RESTORE_STATUS = "blobRestoreStatus"

class UsageUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the unit of measurement.
    """

    COUNT = "Count"
    BYTES = "Bytes"
    SECONDS = "Seconds"
    PERCENT = "Percent"
    COUNTS_PER_SECOND = "CountsPerSecond"
    BYTES_PER_SECOND = "BytesPerSecond"
