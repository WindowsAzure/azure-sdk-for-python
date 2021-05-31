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


class AdministratorName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    ACTIVE_DIRECTORY = "ActiveDirectory"

class AdministratorType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of the sever administrator.
    """

    ACTIVE_DIRECTORY = "ActiveDirectory"

class AdvisorStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the status of availability of this advisor to customers. Possible values are 'GA',
    'PublicPreview', 'LimitedPublicPreview' and 'PrivatePreview'.
    """

    GA = "GA"
    PUBLIC_PREVIEW = "PublicPreview"
    LIMITED_PUBLIC_PREVIEW = "LimitedPublicPreview"
    PRIVATE_PREVIEW = "PrivatePreview"

class AggregationFunctionType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    AVG = "avg"
    MIN = "min"
    MAX = "max"
    STDEV = "stdev"
    SUM = "sum"

class AuthenticationName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "Default"

class AutoExecuteStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the auto-execute status (whether to let the system execute the recommendations) of this
    advisor. Possible values are 'Enabled' and 'Disabled'
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"
    DEFAULT = "Default"

class AutoExecuteStatusInheritedFrom(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the resource from which current value of auto-execute status is inherited. Auto-execute
    status can be set on (and inherited from) different levels in the resource hierarchy. Possible
    values are 'Subscription', 'Server', 'ElasticPool', 'Database' and 'Default' (when status is
    not explicitly set on any level).
    """

    DEFAULT = "Default"
    SUBSCRIPTION = "Subscription"
    SERVER = "Server"
    ELASTIC_POOL = "ElasticPool"
    DATABASE = "Database"

class AutomaticTuningDisabledReason(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Reason description if desired and actual state are different.
    """

    DEFAULT = "Default"
    DISABLED = "Disabled"
    AUTO_CONFIGURED = "AutoConfigured"
    INHERITED_FROM_SERVER = "InheritedFromServer"
    QUERY_STORE_OFF = "QueryStoreOff"
    QUERY_STORE_READ_ONLY = "QueryStoreReadOnly"
    NOT_SUPPORTED = "NotSupported"

class AutomaticTuningMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Automatic tuning desired state.
    """

    INHERIT = "Inherit"
    CUSTOM = "Custom"
    AUTO = "Auto"
    UNSPECIFIED = "Unspecified"

class AutomaticTuningOptionModeActual(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Automatic tuning option actual state.
    """

    OFF = "Off"
    ON = "On"

class AutomaticTuningOptionModeDesired(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Automatic tuning option desired state.
    """

    OFF = "Off"
    ON = "On"
    DEFAULT = "Default"

class AutomaticTuningServerMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Automatic tuning desired state.
    """

    CUSTOM = "Custom"
    AUTO = "Auto"
    UNSPECIFIED = "Unspecified"

class AutomaticTuningServerReason(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Reason description if desired and actual state are different.
    """

    DEFAULT = "Default"
    DISABLED = "Disabled"
    AUTO_CONFIGURED = "AutoConfigured"

class BackupStorageRedundancy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The storage redundancy type of the copied backup
    """

    GEO = "Geo"
    LOCAL = "Local"
    ZONE = "Zone"

class BlobAuditingPolicyState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the state of the audit. If state is Enabled, storageEndpoint or
    isAzureMonitorTargetEnabled are required.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class CapabilityGroup(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    SUPPORTED_EDITIONS = "supportedEditions"
    SUPPORTED_ELASTIC_POOL_EDITIONS = "supportedElasticPoolEditions"
    SUPPORTED_MANAGED_INSTANCE_VERSIONS = "supportedManagedInstanceVersions"
    SUPPORTED_INSTANCE_POOL_EDITIONS = "supportedInstancePoolEditions"
    SUPPORTED_MANAGED_INSTANCE_EDITIONS = "supportedManagedInstanceEditions"

class CapabilityStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the capability.
    """

    VISIBLE = "Visible"
    AVAILABLE = "Available"
    DEFAULT = "Default"
    DISABLED = "Disabled"

class CatalogCollationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Collation of the metadata catalog.
    """

    DATABASE_DEFAULT = "DATABASE_DEFAULT"
    SQL_LATIN1_GENERAL_CP1_CI_AS = "SQL_Latin1_General_CP1_CI_AS"

class CheckNameAvailabilityReason(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The reason code explaining why the name is unavailable. Will be undefined if the name is
    available.
    """

    INVALID = "Invalid"
    ALREADY_EXISTS = "AlreadyExists"

class ColumnDataType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The column data type.
    """

    IMAGE = "image"
    TEXT = "text"
    UNIQUEIDENTIFIER = "uniqueidentifier"
    DATE = "date"
    TIME = "time"
    DATETIME2 = "datetime2"
    DATETIMEOFFSET = "datetimeoffset"
    TINYINT = "tinyint"
    SMALLINT = "smallint"
    INT = "int"
    SMALLDATETIME = "smalldatetime"
    REAL = "real"
    MONEY = "money"
    DATETIME = "datetime"
    FLOAT = "float"
    SQL_VARIANT = "sql_variant"
    NTEXT = "ntext"
    BIT = "bit"
    DECIMAL = "decimal"
    NUMERIC = "numeric"
    SMALLMONEY = "smallmoney"
    BIGINT = "bigint"
    HIERARCHYID = "hierarchyid"
    GEOMETRY = "geometry"
    GEOGRAPHY = "geography"
    VARBINARY = "varbinary"
    VARCHAR = "varchar"
    BINARY = "binary"
    CHAR = "char"
    TIMESTAMP = "timestamp"
    NVARCHAR = "nvarchar"
    NCHAR = "nchar"
    XML = "xml"
    SYSNAME = "sysname"

class ConnectionPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "default"

class CreatedByType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of identity that created the resource.
    """

    USER = "User"
    APPLICATION = "Application"
    MANAGED_IDENTITY = "ManagedIdentity"
    KEY = "Key"

class CreateMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the mode of database creation.
    
    Default: regular database creation.
    
    Copy: creates a database as a copy of an existing database. sourceDatabaseId must be specified
    as the resource ID of the source database.
    
    Secondary: creates a database as a secondary replica of an existing database. sourceDatabaseId
    must be specified as the resource ID of the existing primary database.
    
    PointInTimeRestore: Creates a database by restoring a point in time backup of an existing
    database. sourceDatabaseId must be specified as the resource ID of the existing database, and
    restorePointInTime must be specified.
    
    Recovery: Creates a database by restoring a geo-replicated backup. sourceDatabaseId must be
    specified as the recoverable database resource ID to restore.
    
    Restore: Creates a database by restoring a backup of a deleted database. sourceDatabaseId must
    be specified. If sourceDatabaseId is the database's original resource ID, then
    sourceDatabaseDeletionDate must be specified. Otherwise sourceDatabaseId must be the restorable
    dropped database resource ID and sourceDatabaseDeletionDate is ignored. restorePointInTime may
    also be specified to restore from an earlier point in time.
    
    RestoreLongTermRetentionBackup: Creates a database by restoring from a long term retention
    vault. recoveryServicesRecoveryPointResourceId must be specified as the recovery point resource
    ID.
    
    Copy, Secondary, and RestoreLongTermRetentionBackup are not supported for DataWarehouse
    edition.
    """

    DEFAULT = "Default"
    COPY = "Copy"
    SECONDARY = "Secondary"
    POINT_IN_TIME_RESTORE = "PointInTimeRestore"
    RESTORE = "Restore"
    RECOVERY = "Recovery"
    RESTORE_EXTERNAL_BACKUP = "RestoreExternalBackup"
    RESTORE_EXTERNAL_BACKUP_SECONDARY = "RestoreExternalBackupSecondary"
    RESTORE_LONG_TERM_RETENTION_BACKUP = "RestoreLongTermRetentionBackup"
    ONLINE_SECONDARY = "OnlineSecondary"

class CurrentBackupStorageRedundancy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The storage account type used to store backups for this database.
    """

    GEO = "Geo"
    LOCAL = "Local"
    ZONE = "Zone"

class DatabaseLicenseType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The license type to apply for this database. ``LicenseIncluded`` if you need a license, or
    ``BasePrice`` if you have a license and are eligible for the Azure Hybrid Benefit.
    """

    LICENSE_INCLUDED = "LicenseIncluded"
    BASE_PRICE = "BasePrice"

class DatabaseReadScale(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The state of read-only routing. If enabled, connections that have application intent set to
    readonly in their connection string may be routed to a readonly secondary replica in the same
    region.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class DatabaseState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    ALL = "All"
    LIVE = "Live"
    DELETED = "Deleted"

class DatabaseStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the database.
    """

    ONLINE = "Online"
    RESTORING = "Restoring"
    RECOVERY_PENDING = "RecoveryPending"
    RECOVERING = "Recovering"
    SUSPECT = "Suspect"
    OFFLINE = "Offline"
    STANDBY = "Standby"
    SHUTDOWN = "Shutdown"
    EMERGENCY_MODE = "EmergencyMode"
    AUTO_CLOSED = "AutoClosed"
    COPYING = "Copying"
    CREATING = "Creating"
    INACCESSIBLE = "Inaccessible"
    OFFLINE_SECONDARY = "OfflineSecondary"
    PAUSING = "Pausing"
    PAUSED = "Paused"
    RESUMING = "Resuming"
    SCALING = "Scaling"
    OFFLINE_CHANGING_DW_PERFORMANCE_TIERS = "OfflineChangingDwPerformanceTiers"
    ONLINE_CHANGING_DW_PERFORMANCE_TIERS = "OnlineChangingDwPerformanceTiers"
    DISABLED = "Disabled"

class DataMaskingFunction(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The masking function that is used for the data masking rule.
    """

    DEFAULT = "Default"
    CCN = "CCN"
    EMAIL = "Email"
    NUMBER = "Number"
    SSN = "SSN"
    TEXT = "Text"

class DataMaskingRuleState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The rule state. Used to delete a rule. To delete an existing rule, specify the schemaName,
    tableName, columnName, maskingFunction, and specify ruleState as disabled. However, if the rule
    doesn't already exist, the rule will be created with ruleState set to enabled, regardless of
    the provided value of ruleState.
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class DataMaskingState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The state of the data masking policy.
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class DataWarehouseUserActivityName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    CURRENT = "current"

class DayOfWeek(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Day of maintenance window.
    """

    SUNDAY = "Sunday"
    MONDAY = "Monday"
    TUESDAY = "Tuesday"
    WEDNESDAY = "Wednesday"
    THURSDAY = "Thursday"
    FRIDAY = "Friday"
    SATURDAY = "Saturday"

class DnsRefreshConfigurationPropertiesStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the DNS refresh operation.
    """

    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

class ElasticPoolLicenseType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The license type to apply for this elastic pool.
    """

    LICENSE_INCLUDED = "LicenseIncluded"
    BASE_PRICE = "BasePrice"

class ElasticPoolState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The state of the elastic pool.
    """

    CREATING = "Creating"
    READY = "Ready"
    DISABLED = "Disabled"

class EncryptionProtectorName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    CURRENT = "current"

class Enum81(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    ALL = "All"
    ERROR = "Error"
    WARNING = "Warning"
    SUCCESS = "Success"

class FailoverGroupReplicationRole(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Local replication role of the failover group instance.
    """

    PRIMARY = "Primary"
    SECONDARY = "Secondary"

class GeoBackupPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "Default"

class GeoBackupPolicyState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The state of the geo backup policy.
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class IdentityType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The identity type. Set this to 'SystemAssigned' in order to automatically create and assign an
    Azure Active Directory principal for the resource.
    """

    NONE = "None"
    SYSTEM_ASSIGNED = "SystemAssigned"
    USER_ASSIGNED = "UserAssigned"

class ImplementationMethod(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the method in which this recommended action can be manually implemented. e.g., TSql,
    AzurePowerShell.
    """

    T_SQL = "TSql"
    AZURE_POWER_SHELL = "AzurePowerShell"

class InstanceFailoverGroupReplicationRole(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Local replication role of the failover group instance.
    """

    PRIMARY = "Primary"
    SECONDARY = "Secondary"

class InstancePoolLicenseType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The license type. Possible values are 'LicenseIncluded' (price for SQL license is included) and
    'BasePrice' (without SQL license price).
    """

    LICENSE_INCLUDED = "LicenseIncluded"
    BASE_PRICE = "BasePrice"

class IsRetryable(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets whether the error could be ignored and recommended action could be retried. Possible
    values are: Yes/No
    """

    YES = "Yes"
    NO = "No"

class JobAgentState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The state of the job agent.
    """

    CREATING = "Creating"
    READY = "Ready"
    UPDATING = "Updating"
    DELETING = "Deleting"
    DISABLED = "Disabled"

class JobExecutionLifecycle(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The detailed state of the job execution.
    """

    CREATED = "Created"
    IN_PROGRESS = "InProgress"
    WAITING_FOR_CHILD_JOB_EXECUTIONS = "WaitingForChildJobExecutions"
    WAITING_FOR_RETRY = "WaitingForRetry"
    SUCCEEDED = "Succeeded"
    SUCCEEDED_WITH_SKIPPED = "SucceededWithSkipped"
    FAILED = "Failed"
    TIMED_OUT = "TimedOut"
    CANCELED = "Canceled"
    SKIPPED = "Skipped"

class JobScheduleType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Schedule interval type
    """

    ONCE = "Once"
    RECURRING = "Recurring"

class JobStepActionSource(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The source of the action to execute.
    """

    INLINE = "Inline"

class JobStepActionType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of action being executed by the job step.
    """

    T_SQL = "TSql"

class JobStepOutputType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The output destination type.
    """

    SQL_DATABASE = "SqlDatabase"

class JobTargetGroupMembershipType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Whether the target is included or excluded from the group.
    """

    INCLUDE = "Include"
    EXCLUDE = "Exclude"

class JobTargetType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the target.
    """

    TARGET_GROUP = "TargetGroup"
    SQL_DATABASE = "SqlDatabase"
    SQL_ELASTIC_POOL = "SqlElasticPool"
    SQL_SHARD_MAP = "SqlShardMap"
    SQL_SERVER = "SqlServer"

class LedgerDigestUploadsName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    CURRENT = "current"

class LedgerDigestUploadsState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the state of ledger digest upload.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class LogSizeUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The units that the limit is expressed in.
    """

    MEGABYTES = "Megabytes"
    GIGABYTES = "Gigabytes"
    TERABYTES = "Terabytes"
    PETABYTES = "Petabytes"
    PERCENT = "Percent"

class LongTermRetentionPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "default"

class ManagedDatabaseCreateMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Managed database create mode. PointInTimeRestore: Create a database by restoring a point in
    time backup of an existing database. SourceDatabaseName, SourceManagedInstanceName and
    PointInTime must be specified. RestoreExternalBackup: Create a database by restoring from
    external backup files. Collation, StorageContainerUri and StorageContainerSasToken must be
    specified. Recovery: Creates a database by restoring a geo-replicated backup.
    RecoverableDatabaseId must be specified as the recoverable database resource ID to restore.
    RestoreLongTermRetentionBackup: Create a database by restoring from a long term retention
    backup (longTermRetentionBackupResourceId required).
    """

    DEFAULT = "Default"
    RESTORE_EXTERNAL_BACKUP = "RestoreExternalBackup"
    POINT_IN_TIME_RESTORE = "PointInTimeRestore"
    RECOVERY = "Recovery"
    RESTORE_LONG_TERM_RETENTION_BACKUP = "RestoreLongTermRetentionBackup"

class ManagedDatabaseStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Status of the database.
    """

    ONLINE = "Online"
    OFFLINE = "Offline"
    SHUTDOWN = "Shutdown"
    CREATING = "Creating"
    INACCESSIBLE = "Inaccessible"
    RESTORING = "Restoring"
    UPDATING = "Updating"

class ManagedInstanceAdministratorType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of the managed instance administrator.
    """

    ACTIVE_DIRECTORY = "ActiveDirectory"

class ManagedInstanceLicenseType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The license type. Possible values are 'LicenseIncluded' (regular price inclusive of a new SQL
    license) and 'BasePrice' (discounted AHB price for bringing your own SQL licenses).
    """

    LICENSE_INCLUDED = "LicenseIncluded"
    BASE_PRICE = "BasePrice"

class ManagedInstanceLongTermRetentionPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "default"

class ManagedInstancePropertiesProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    CREATING = "Creating"
    DELETING = "Deleting"
    UPDATING = "Updating"
    UNKNOWN = "Unknown"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

class ManagedInstanceProxyOverride(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Connection type used for connecting to the instance.
    """

    PROXY = "Proxy"
    REDIRECT = "Redirect"
    DEFAULT = "Default"

class ManagedServerCreateMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the mode of database creation.
    
    Default: Regular instance creation.
    
    Restore: Creates an instance by restoring a set of backups to specific point in time.
    RestorePointInTime and SourceManagedInstanceId must be specified.
    """

    DEFAULT = "Default"
    POINT_IN_TIME_RESTORE = "PointInTimeRestore"

class ManagedShortTermRetentionPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "default"

class ManagementOperationState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The operation state.
    """

    PENDING = "Pending"
    IN_PROGRESS = "InProgress"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCEL_IN_PROGRESS = "CancelInProgress"
    CANCELLED = "Cancelled"

class MaxSizeUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The units that the limit is expressed in.
    """

    MEGABYTES = "Megabytes"
    GIGABYTES = "Gigabytes"
    TERABYTES = "Terabytes"
    PETABYTES = "Petabytes"

class MetricType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    CPU = "cpu"
    IO = "io"
    LOG_IO = "logIo"
    DURATION = "duration"
    DTU = "dtu"

class OperationMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Operation Mode.
    """

    POLYBASE_IMPORT = "PolybaseImport"

class OperationOrigin(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The intended executor of the operation.
    """

    USER = "user"
    SYSTEM = "system"

class PauseDelayTimeUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Unit of time that delay is expressed in
    """

    MINUTES = "Minutes"

class PerformanceLevelUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Unit type used to measure performance level.
    """

    DTU = "DTU"
    V_CORES = "VCores"

class PrimaryAggregationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The primary aggregation type defining how metric values are displayed.
    """

    NONE = "None"
    AVERAGE = "Average"
    COUNT = "Count"
    MINIMUM = "Minimum"
    MAXIMUM = "Maximum"
    TOTAL = "Total"

class PrincipalType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Principal Type of the sever administrator.
    """

    USER = "User"
    GROUP = "Group"
    APPLICATION = "Application"

class PrivateEndpointProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """State of the private endpoint connection.
    """

    APPROVING = "Approving"
    READY = "Ready"
    DROPPING = "Dropping"
    FAILED = "Failed"
    REJECTING = "Rejecting"

class PrivateLinkServiceConnectionStateActionsRequire(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The actions required for private link service connection.
    """

    NONE = "None"

class PrivateLinkServiceConnectionStateStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The private link service connection status.
    """

    APPROVED = "Approved"
    PENDING = "Pending"
    REJECTED = "Rejected"
    DISCONNECTED = "Disconnected"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The ARM provisioning state of the job execution.
    """

    CREATED = "Created"
    IN_PROGRESS = "InProgress"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"

class QueryMetricUnitType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The unit of the metric.
    """

    PERCENTAGE = "percentage"
    KB = "KB"
    MICROSECONDS = "microseconds"
    COUNT = "count"

class QueryTimeGrainType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Interval type (length).
    """

    PT1_H = "PT1H"
    P1_D = "P1D"

class ReadOnlyEndpointFailoverPolicy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Failover policy of the read-only endpoint for the failover group.
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class ReadWriteEndpointFailoverPolicy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Failover policy of the read-write endpoint for the failover group. If failoverPolicy is
    Automatic then failoverWithDataLossGracePeriodMinutes is required.
    """

    MANUAL = "Manual"
    AUTOMATIC = "Automatic"

class RecommendedActionCurrentState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Current state the recommended action is in. Some commonly used states are: Active      ->
    recommended action is active and no action has been taken yet. Pending     -> recommended
    action is approved for and is awaiting execution. Executing   -> recommended action is being
    applied on the user database. Verifying   -> recommended action was applied and is being
    verified of its usefulness by the system. Success     -> recommended action was applied and
    improvement found during verification. Pending Revert  -> verification found little or no
    improvement so recommended action is queued for revert or user has manually reverted. Reverting
    -> changes made while applying recommended action are being reverted on the user database.
    Reverted    -> successfully reverted the changes made by recommended action on user database.
    Ignored     -> user explicitly ignored/discarded the recommended action.
    """

    ACTIVE = "Active"
    PENDING = "Pending"
    EXECUTING = "Executing"
    VERIFYING = "Verifying"
    PENDING_REVERT = "PendingRevert"
    REVERT_CANCELLED = "RevertCancelled"
    REVERTING = "Reverting"
    REVERTED = "Reverted"
    IGNORED = "Ignored"
    EXPIRED = "Expired"
    MONITORING = "Monitoring"
    RESOLVED = "Resolved"
    SUCCESS = "Success"
    ERROR = "Error"

class RecommendedActionInitiatedBy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets if approval for applying this recommended action was given by user/system.
    """

    USER = "User"
    SYSTEM = "System"

class RecommendedSensitivityLabelUpdateKind(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    ENABLE = "enable"
    DISABLE = "disable"

class ReplicaType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    PRIMARY = "Primary"
    READABLE_SECONDARY = "ReadableSecondary"

class RequestedBackupStorageRedundancy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The storage redundancy type of the copied backup
    """

    GEO = "Geo"
    LOCAL = "Local"
    ZONE = "Zone"

class RestorableDroppedDatabasePropertiesBackupStorageRedundancy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The storage account type used to store backups for this database.
    """

    GEO = "Geo"
    LOCAL = "Local"
    ZONE = "Zone"

class RestoreDetailsName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "Default"

class RestorePointType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of restore point
    """

    CONTINUOUS = "CONTINUOUS"
    DISCRETE = "DISCRETE"

class SampleName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The name of the sample schema to apply when creating this database.
    """

    ADVENTURE_WORKS_LT = "AdventureWorksLT"
    WIDE_WORLD_IMPORTERS_STD = "WideWorldImportersStd"
    WIDE_WORLD_IMPORTERS_FULL = "WideWorldImportersFull"

class SecondaryType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The secondary type of the database if it is a secondary.  Valid values are Geo and Named.
    """

    GEO = "Geo"
    NAMED = "Named"

class SecurityAlertPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "default"

class SecurityAlertPolicyNameAutoGenerated(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "Default"

class SecurityAlertPolicyState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the state of the policy, whether it is enabled or disabled or a policy has not been
    applied yet on the specific database.
    """

    NEW = "New"
    ENABLED = "Enabled"
    DISABLED = "Disabled"

class SecurityAlertsPolicyState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the state of the policy, whether it is enabled or disabled or a policy has not been
    applied yet on the specific database.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class SecurityEventType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the security event.
    """

    UNDEFINED = "Undefined"
    SQL_INJECTION_VULNERABILITY = "SqlInjectionVulnerability"
    SQL_INJECTION_EXPLOIT = "SqlInjectionExploit"

class SensitivityLabelRank(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class SensitivityLabelSource(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    CURRENT = "current"
    RECOMMENDED = "recommended"

class SensitivityLabelUpdateKind(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    SET = "set"
    REMOVE = "remove"

class ServerConnectionType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The server connection type.
    """

    DEFAULT = "Default"
    PROXY = "Proxy"
    REDIRECT = "Redirect"

class ServerKeyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The encryption protector type like 'ServiceManaged', 'AzureKeyVault'.
    """

    SERVICE_MANAGED = "ServiceManaged"
    AZURE_KEY_VAULT = "AzureKeyVault"

class ServerPublicNetworkAccess(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Whether or not public endpoint access is allowed for this server.  Value is optional but if
    passed in, must be 'Enabled' or 'Disabled'
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class ServerTrustGroupPropertiesTrustScopesItem(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    GLOBAL_TRANSACTIONS = "GlobalTransactions"
    SERVICE_BROKER = "ServiceBroker"

class ServerWorkspaceFeature(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Whether or not existing server has a workspace created and if it allows connection from
    workspace
    """

    CONNECTED = "Connected"
    DISCONNECTED = "Disconnected"

class ServiceObjectiveName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The serviceLevelObjective for SLO usage metric.
    """

    SYSTEM = "System"
    SYSTEM0 = "System0"
    SYSTEM1 = "System1"
    SYSTEM2 = "System2"
    SYSTEM3 = "System3"
    SYSTEM4 = "System4"
    SYSTEM2_L = "System2L"
    SYSTEM3_L = "System3L"
    SYSTEM4_L = "System4L"
    FREE = "Free"
    BASIC = "Basic"
    S0 = "S0"
    S1 = "S1"
    S2 = "S2"
    S3 = "S3"
    S4 = "S4"
    S6 = "S6"
    S7 = "S7"
    S9 = "S9"
    S12 = "S12"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P6 = "P6"
    P11 = "P11"
    P15 = "P15"
    PRS1 = "PRS1"
    PRS2 = "PRS2"
    PRS4 = "PRS4"
    PRS6 = "PRS6"
    DW100 = "DW100"
    DW200 = "DW200"
    DW300 = "DW300"
    DW400 = "DW400"
    DW500 = "DW500"
    DW600 = "DW600"
    DW1000 = "DW1000"
    DW1200 = "DW1200"
    DW1000_C = "DW1000c"
    DW1500 = "DW1500"
    DW1500_C = "DW1500c"
    DW2000 = "DW2000"
    DW2000_C = "DW2000c"
    DW3000 = "DW3000"
    DW2500_C = "DW2500c"
    DW3000_C = "DW3000c"
    DW6000 = "DW6000"
    DW5000_C = "DW5000c"
    DW6000_C = "DW6000c"
    DW7500_C = "DW7500c"
    DW10000_C = "DW10000c"
    DW15000_C = "DW15000c"
    DW30000_C = "DW30000c"
    DS100 = "DS100"
    DS200 = "DS200"
    DS300 = "DS300"
    DS400 = "DS400"
    DS500 = "DS500"
    DS600 = "DS600"
    DS1000 = "DS1000"
    DS1200 = "DS1200"
    DS1500 = "DS1500"
    DS2000 = "DS2000"
    ELASTIC_POOL = "ElasticPool"

class ShortTermRetentionPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "default"

class SqlAgentConfigurationPropertiesState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The state of Sql Agent.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class StorageAccountType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The storage account type used to store backups for this instance. The options are LRS
    (LocallyRedundantStorage), ZRS (ZoneRedundantStorage) and GRS (GeoRedundantStorage)
    """

    GRS = "GRS"
    LRS = "LRS"
    ZRS = "ZRS"

class StorageCapabilityStorageAccountType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The storage account type for the database's backups.
    """

    GRS = "GRS"
    LRS = "LRS"
    ZRS = "ZRS"

class StorageKeyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Storage key type.
    """

    SHARED_ACCESS_KEY = "SharedAccessKey"
    STORAGE_ACCESS_KEY = "StorageAccessKey"

class SyncAgentState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """State of the sync agent.
    """

    ONLINE = "Online"
    OFFLINE = "Offline"
    NEVER_CONNECTED = "NeverConnected"

class SyncConflictResolutionPolicy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Conflict resolution policy of the sync group.
    """

    HUB_WIN = "HubWin"
    MEMBER_WIN = "MemberWin"

class SyncDirection(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Sync direction of the sync member.
    """

    BIDIRECTIONAL = "Bidirectional"
    ONE_WAY_MEMBER_TO_HUB = "OneWayMemberToHub"
    ONE_WAY_HUB_TO_MEMBER = "OneWayHubToMember"

class SyncGroupLogType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of the sync group log.
    """

    ALL = "All"
    ERROR = "Error"
    WARNING = "Warning"
    SUCCESS = "Success"

class SyncGroupState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Sync state of the sync group.
    """

    NOT_READY = "NotReady"
    ERROR = "Error"
    WARNING = "Warning"
    PROGRESSING = "Progressing"
    GOOD = "Good"

class SyncMemberDbType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of the sync agent linked database.
    """

    AZURE_SQL_DATABASE = "AzureSqlDatabase"
    SQL_SERVER_DATABASE = "SqlServerDatabase"

class SyncMemberState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Sync state of the sync member.
    """

    SYNC_IN_PROGRESS = "SyncInProgress"
    SYNC_SUCCEEDED = "SyncSucceeded"
    SYNC_FAILED = "SyncFailed"
    DISABLED_TOMBSTONE_CLEANUP = "DisabledTombstoneCleanup"
    DISABLED_BACKUP_RESTORE = "DisabledBackupRestore"
    SYNC_SUCCEEDED_WITH_WARNINGS = "SyncSucceededWithWarnings"
    SYNC_CANCELLING = "SyncCancelling"
    SYNC_CANCELLED = "SyncCancelled"
    UN_PROVISIONED = "UnProvisioned"
    PROVISIONING = "Provisioning"
    PROVISIONED = "Provisioned"
    PROVISION_FAILED = "ProvisionFailed"
    DE_PROVISIONING = "DeProvisioning"
    DE_PROVISIONED = "DeProvisioned"
    DE_PROVISION_FAILED = "DeProvisionFailed"
    REPROVISIONING = "Reprovisioning"
    REPROVISION_FAILED = "ReprovisionFailed"
    UN_REPROVISIONED = "UnReprovisioned"

class TableTemporalType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The table temporal type.
    """

    NON_TEMPORAL_TABLE = "NonTemporalTable"
    HISTORY_TABLE = "HistoryTable"
    SYSTEM_VERSIONED_TEMPORAL_TABLE = "SystemVersionedTemporalTable"

class TargetBackupStorageRedundancy(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The storage redundancy type of the copied backup
    """

    GEO = "Geo"
    LOCAL = "Local"
    ZONE = "Zone"

class TransparentDataEncryptionActivityStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the database.
    """

    ENCRYPTING = "Encrypting"
    DECRYPTING = "Decrypting"

class TransparentDataEncryptionName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    CURRENT = "current"

class TransparentDataEncryptionState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the state of the transparent data encryption.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class TransparentDataEncryptionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the database transparent data encryption.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class UnitDefinitionType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The unit of the metric.
    """

    COUNT = "Count"
    BYTES = "Bytes"
    SECONDS = "Seconds"
    PERCENT = "Percent"
    COUNT_PER_SECOND = "CountPerSecond"
    BYTES_PER_SECOND = "BytesPerSecond"

class UnitType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The unit of the metric.
    """

    COUNT = "count"
    BYTES = "bytes"
    SECONDS = "seconds"
    PERCENT = "percent"
    COUNT_PER_SECOND = "countPerSecond"
    BYTES_PER_SECOND = "bytesPerSecond"

class UpsertManagedServerOperationStepStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    NOT_STARTED = "NotStarted"
    IN_PROGRESS = "InProgress"
    SLOWED_DOWN = "SlowedDown"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELED = "Canceled"

class VirtualNetworkRuleState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Virtual Network Rule State
    """

    INITIALIZING = "Initializing"
    IN_PROGRESS = "InProgress"
    READY = "Ready"
    FAILED = "Failed"
    DELETING = "Deleting"
    UNKNOWN = "Unknown"

class VulnerabilityAssessmentName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "default"

class VulnerabilityAssessmentPolicyBaselineName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    MASTER = "master"
    DEFAULT = "default"

class VulnerabilityAssessmentScanState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The scan status.
    """

    PASSED = "Passed"
    FAILED = "Failed"
    FAILED_TO_RUN = "FailedToRun"
    IN_PROGRESS = "InProgress"

class VulnerabilityAssessmentScanTriggerType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The scan trigger type.
    """

    ON_DEMAND = "OnDemand"
    RECURRING = "Recurring"
