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


class AccountType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of storage accessed on the storage account.
    """

    GENERAL_PURPOSE_STORAGE = "GeneralPurposeStorage"
    BLOB_STORAGE = "BlobStorage"

class AlertSeverity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Severity of the alert.
    """

    INFORMATIONAL = "Informational"
    WARNING = "Warning"
    CRITICAL = "Critical"

class AuthenticationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The authentication type.
    """

    INVALID = "Invalid"
    AZURE_ACTIVE_DIRECTORY = "AzureActiveDirectory"

class AzureContainerDataFormat(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Storage format used for the file represented by the share.
    """

    BLOCK_BLOB = "BlockBlob"
    PAGE_BLOB = "PageBlob"
    AZURE_FILE = "AzureFile"

class ClientPermissionType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of access to be allowed for the client.
    """

    NO_ACCESS = "NoAccess"
    READ_ONLY = "ReadOnly"
    READ_WRITE = "ReadWrite"

class ContainerStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Current status of the container.
    """

    OK = "OK"
    OFFLINE = "Offline"
    UNKNOWN = "Unknown"
    UPDATING = "Updating"
    NEEDS_ATTENTION = "NeedsAttention"

class DataBoxEdgeDeviceStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the Data Box Edge/Gateway device.
    """

    READY_TO_SETUP = "ReadyToSetup"
    ONLINE = "Online"
    OFFLINE = "Offline"
    NEEDS_ATTENTION = "NeedsAttention"
    DISCONNECTED = "Disconnected"
    PARTIALLY_DISCONNECTED = "PartiallyDisconnected"
    MAINTENANCE = "Maintenance"

class DataPolicy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Data policy of the share.
    """

    CLOUD = "Cloud"
    LOCAL = "Local"

class DayOfWeek(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    SUNDAY = "Sunday"
    MONDAY = "Monday"
    TUESDAY = "Tuesday"
    WEDNESDAY = "Wednesday"
    THURSDAY = "Thursday"
    FRIDAY = "Friday"
    SATURDAY = "Saturday"

class DeviceType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the Data Box Edge/Gateway device.
    """

    DATA_BOX_EDGE_DEVICE = "DataBoxEdgeDevice"

class DownloadPhase(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The download phase.
    """

    UNKNOWN = "Unknown"
    INITIALIZING = "Initializing"
    DOWNLOADING = "Downloading"
    VERIFYING = "Verifying"

class EncryptionAlgorithm(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The algorithm used to encrypt "Value".
    """

    NONE = "None"
    AES256 = "AES256"
    RSAES_PKCS1_V1_5 = "RSAES_PKCS1_v_1_5"

class InstallRebootBehavior(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates if updates are available and at least one of the updates needs a reboot.
    """

    NEVER_REBOOTS = "NeverReboots"
    REQUIRES_REBOOT = "RequiresReboot"
    REQUEST_REBOOT = "RequestReboot"

class JobStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current status of the job.
    """

    INVALID = "Invalid"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"
    PAUSED = "Paused"
    SCHEDULED = "Scheduled"

class JobType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the job.
    """

    INVALID = "Invalid"
    SCAN_FOR_UPDATES = "ScanForUpdates"
    DOWNLOAD_UPDATES = "DownloadUpdates"
    INSTALL_UPDATES = "InstallUpdates"
    REFRESH_SHARE = "RefreshShare"
    REFRESH_CONTAINER = "RefreshContainer"

class MetricAggregationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Metric aggregation type.
    """

    NOT_SPECIFIED = "NotSpecified"
    NONE = "None"
    AVERAGE = "Average"
    MINIMUM = "Minimum"
    MAXIMUM = "Maximum"
    TOTAL = "Total"
    COUNT = "Count"

class MetricCategory(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Metric category.
    """

    CAPACITY = "Capacity"
    TRANSACTION = "Transaction"

class MetricUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Metric units.
    """

    NOT_SPECIFIED = "NotSpecified"
    PERCENT = "Percent"
    COUNT = "Count"
    SECONDS = "Seconds"
    MILLISECONDS = "Milliseconds"
    BYTES = "Bytes"
    BYTES_PER_SECOND = "BytesPerSecond"
    COUNT_PER_SECOND = "CountPerSecond"

class MonitoringStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Current monitoring status of the share.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class NetworkAdapterDHCPStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Value indicating whether this adapter has DHCP enabled.
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class NetworkAdapterRDMAStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Value indicating whether this adapter is RDMA capable.
    """

    INCAPABLE = "Incapable"
    CAPABLE = "Capable"

class NetworkAdapterStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Value indicating whether this adapter is valid.
    """

    INACTIVE = "Inactive"
    ACTIVE = "Active"

class NetworkGroup(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The network group.
    """

    NONE = "None"
    NON_RDMA = "NonRDMA"
    RDMA = "RDMA"

class NodeStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current status of the individual node
    """

    UNKNOWN = "Unknown"
    UP = "Up"
    DOWN = "Down"
    REBOOTING = "Rebooting"
    SHUTTING_DOWN = "ShuttingDown"

class OrderState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Status of the order as per the allowed status types.
    """

    UNTRACKED = "Untracked"
    AWAITING_FULFILMENT = "AwaitingFulfilment"
    AWAITING_PREPARATION = "AwaitingPreparation"
    AWAITING_SHIPMENT = "AwaitingShipment"
    SHIPPED = "Shipped"
    ARRIVING = "Arriving"
    DELIVERED = "Delivered"
    REPLACEMENT_REQUESTED = "ReplacementRequested"
    LOST_DEVICE = "LostDevice"
    DECLINED = "Declined"
    RETURN_INITIATED = "ReturnInitiated"
    AWAITING_RETURN_SHIPMENT = "AwaitingReturnShipment"
    SHIPPED_BACK = "ShippedBack"
    COLLECTED_AT_MICROSOFT = "CollectedAtMicrosoft"

class PlatformType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Host OS supported by the IoT role.
    """

    WINDOWS = "Windows"
    LINUX = "Linux"

class RoleStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Role status.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class RoleTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    IOT = "IOT"
    ASA = "ASA"
    FUNCTIONS = "Functions"
    COGNITIVE = "Cognitive"

class ShareAccessProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Access protocol to be used by the share.
    """

    SMB = "SMB"
    NFS = "NFS"

class ShareAccessType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of access to be allowed on the share for this user.
    """

    CHANGE = "Change"
    READ = "Read"
    CUSTOM = "Custom"

class ShareStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Current status of the share.
    """

    OFFLINE = "Offline"
    UNKNOWN = "Unknown"
    OK = "OK"
    UPDATING = "Updating"
    NEEDS_ATTENTION = "NeedsAttention"

class SkuName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The Sku name
    """

    GATEWAY = "Gateway"
    EDGE = "Edge"
    TEA1_NODE = "TEA_1Node"
    TEA1_NODE_UPS = "TEA_1Node_UPS"
    TEA1_NODE_HEATER = "TEA_1Node_Heater"
    TEA1_NODE_UPS_HEATER = "TEA_1Node_UPS_Heater"
    TEA4_NODE_HEATER = "TEA_4Node_Heater"
    TEA4_NODE_UPS_HEATER = "TEA_4Node_UPS_Heater"
    TMA = "TMA"

class SkuRestrictionReasonCode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The SKU restriction reason.
    """

    NOT_AVAILABLE_FOR_SUBSCRIPTION = "NotAvailableForSubscription"
    QUOTA_ID = "QuotaId"

class SkuTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The Sku tier
    """

    STANDARD = "Standard"

class SSLStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Signifies whether SSL needs to be enabled or not.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class StorageAccountStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Current status of the storage account
    """

    OK = "OK"
    OFFLINE = "Offline"
    UNKNOWN = "Unknown"
    UPDATING = "Updating"
    NEEDS_ATTENTION = "NeedsAttention"

class TimeGrain(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    PT1_M = "PT1M"
    PT5_M = "PT5M"
    PT15_M = "PT15M"
    PT30_M = "PT30M"
    PT1_H = "PT1H"
    PT6_H = "PT6H"
    PT12_H = "PT12H"
    PT1_D = "PT1D"

class TriggerEventType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Trigger Kind.
    """

    FILE_EVENT = "FileEvent"
    PERIODIC_TIMER_EVENT = "PeriodicTimerEvent"

class UpdateOperation(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current update operation.
    """

    NONE = "None"
    SCAN = "Scan"
    DOWNLOAD = "Download"
    INSTALL = "Install"

class UpdateOperationStage(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Current stage of the update operation.
    """

    UNKNOWN = "Unknown"
    INITIAL = "Initial"
    SCAN_STARTED = "ScanStarted"
    SCAN_COMPLETE = "ScanComplete"
    SCAN_FAILED = "ScanFailed"
    DOWNLOAD_STARTED = "DownloadStarted"
    DOWNLOAD_COMPLETE = "DownloadComplete"
    DOWNLOAD_FAILED = "DownloadFailed"
    INSTALL_STARTED = "InstallStarted"
    INSTALL_COMPLETE = "InstallComplete"
    INSTALL_FAILED = "InstallFailed"
    REBOOT_INITIATED = "RebootInitiated"
    SUCCESS = "Success"
    FAILURE = "Failure"
    RESCAN_STARTED = "RescanStarted"
    RESCAN_COMPLETE = "RescanComplete"
    RESCAN_FAILED = "RescanFailed"

class UserType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of the user.
    """

    SHARE = "Share"
    LOCAL_MANAGEMENT = "LocalManagement"
    ARM = "ARM"
