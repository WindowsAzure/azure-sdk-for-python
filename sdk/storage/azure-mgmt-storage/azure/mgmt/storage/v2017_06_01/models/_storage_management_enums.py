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

class Bypass(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are
    any combination of Logging|Metrics|AzureServices (For example, "Logging, Metrics"), or None to
    bypass none of those traffics.
    """

    NONE = "None"
    LOGGING = "Logging"
    METRICS = "Metrics"
    AZURE_SERVICES = "AzureServices"

class DefaultAction(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the default action of allow or deny when no other rules match.
    """

    ALLOW = "Allow"
    DENY = "Deny"

class HttpProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The protocol permitted for a request made with the account SAS.
    """

    HTTPS_HTTP = "https,http"
    HTTPS = "https"

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

class Kind(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates the type of storage account.
    """

    STORAGE = "Storage"
    BLOB_STORAGE = "BlobStorage"

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

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the status of the storage account at the time the operation was called.
    """

    CREATING = "Creating"
    RESOLVING_DNS = "ResolvingDNS"
    SUCCEEDED = "Succeeded"

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

class Services(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The signed services accessible with the account SAS. Possible values include: Blob (b), Queue
    (q), Table (t), File (f).
    """

    B = "b"
    Q = "q"
    T = "t"
    F = "f"

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
    """Gets or sets the sku name. Required for account creation; optional for update. Note that in
    older versions, sku name was called accountType.
    """

    STANDARD_LRS = "Standard_LRS"
    STANDARD_GRS = "Standard_GRS"
    STANDARD_RAGRS = "Standard_RAGRS"
    STANDARD_ZRS = "Standard_ZRS"
    PREMIUM_LRS = "Premium_LRS"

class SkuTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the sku tier. This is based on the SKU name.
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

class UsageUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the unit of measurement.
    """

    COUNT = "Count"
    BYTES = "Bytes"
    SECONDS = "Seconds"
    PERCENT = "Percent"
    COUNTS_PER_SECOND = "CountsPerSecond"
    BYTES_PER_SECOND = "BytesPerSecond"
