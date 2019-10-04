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


class StorageType(str, Enum):

    invalid = "Invalid"
    geo_redundant = "GeoRedundant"
    locally_redundant = "LocallyRedundant"


class StorageTypeState(str, Enum):

    invalid = "Invalid"
    locked = "Locked"
    unlocked = "Unlocked"


class EnhancedSecurityState(str, Enum):

    invalid = "Invalid"
    enabled = "Enabled"
    disabled = "Disabled"


class SoftDeleteState(str, Enum):

    invalid = "Invalid"
    enabled = "Enabled"
    disabled = "Disabled"


class ProtectionState(str, Enum):

    invalid = "Invalid"
    ir_pending = "IRPending"
    protected = "Protected"
    protection_error = "ProtectionError"
    protection_stopped = "ProtectionStopped"
    protection_paused = "ProtectionPaused"


class HealthStatus(str, Enum):

    passed = "Passed"
    action_required = "ActionRequired"
    action_suggested = "ActionSuggested"
    invalid = "Invalid"


class RecoveryType(str, Enum):

    invalid = "Invalid"
    original_location = "OriginalLocation"
    alternate_location = "AlternateLocation"
    restore_disks = "RestoreDisks"
    offline = "Offline"


class CopyOptions(str, Enum):

    invalid = "Invalid"
    create_copy = "CreateCopy"
    skip = "Skip"
    overwrite = "Overwrite"
    fail_on_conflict = "FailOnConflict"


class RestoreRequestType(str, Enum):

    invalid = "Invalid"
    full_share_restore = "FullShareRestore"
    item_level_restore = "ItemLevelRestore"


class JobSupportedAction(str, Enum):

    invalid = "Invalid"
    cancellable = "Cancellable"
    retriable = "Retriable"


class ProtectedItemState(str, Enum):

    invalid = "Invalid"
    ir_pending = "IRPending"
    protected = "Protected"
    protection_error = "ProtectionError"
    protection_stopped = "ProtectionStopped"
    protection_paused = "ProtectionPaused"


class LastBackupStatus(str, Enum):

    invalid = "Invalid"
    healthy = "Healthy"
    unhealthy = "Unhealthy"
    ir_pending = "IRPending"


class ProtectedItemHealthStatus(str, Enum):

    invalid = "Invalid"
    healthy = "Healthy"
    unhealthy = "Unhealthy"
    not_reachable = "NotReachable"
    ir_pending = "IRPending"


class RestorePointType(str, Enum):

    invalid = "Invalid"
    full = "Full"
    log = "Log"
    differential = "Differential"


class OverwriteOptions(str, Enum):

    invalid = "Invalid"
    fail_on_conflict = "FailOnConflict"
    overwrite = "Overwrite"


class RecoveryMode(str, Enum):

    invalid = "Invalid"
    file_recovery = "FileRecovery"
    workload_recovery = "WorkloadRecovery"


class SQLDataDirectoryType(str, Enum):

    invalid = "Invalid"
    data = "Data"
    log = "Log"


class RestorePointQueryType(str, Enum):

    invalid = "Invalid"
    full = "Full"
    log = "Log"
    differential = "Differential"
    full_and_differential = "FullAndDifferential"
    all = "All"


class RecoveryPointTierType(str, Enum):

    invalid = "Invalid"
    instant_rp = "InstantRP"
    hardened_rp = "HardenedRP"


class RecoveryPointTierStatus(str, Enum):

    invalid = "Invalid"
    valid = "Valid"
    disabled = "Disabled"
    deleted = "Deleted"


class BackupManagementType(str, Enum):

    invalid = "Invalid"
    azure_iaas_vm = "AzureIaasVM"
    mab = "MAB"
    dpm = "DPM"
    azure_backup_server = "AzureBackupServer"
    azure_sql = "AzureSql"
    azure_storage = "AzureStorage"
    azure_workload = "AzureWorkload"
    default_backup = "DefaultBackup"


class JobStatus(str, Enum):

    invalid = "Invalid"
    in_progress = "InProgress"
    completed = "Completed"
    failed = "Failed"
    completed_with_warnings = "CompletedWithWarnings"
    cancelled = "Cancelled"
    cancelling = "Cancelling"


class JobOperationType(str, Enum):

    invalid = "Invalid"
    register = "Register"
    un_register = "UnRegister"
    configure_backup = "ConfigureBackup"
    backup = "Backup"
    restore = "Restore"
    disable_backup = "DisableBackup"
    delete_backup_data = "DeleteBackupData"
    cross_region_restore = "CrossRegionRestore"
    undelete = "Undelete"


class MabServerType(str, Enum):

    invalid = "Invalid"
    unknown = "Unknown"
    iaas_vm_container = "IaasVMContainer"
    iaas_vm_service_container = "IaasVMServiceContainer"
    dpm_container = "DPMContainer"
    azure_backup_server_container = "AzureBackupServerContainer"
    mab_container = "MABContainer"
    cluster = "Cluster"
    azure_sql_container = "AzureSqlContainer"
    windows = "Windows"
    vcenter = "VCenter"
    vm_app_container = "VMAppContainer"
    sqlag_work_load_container = "SQLAGWorkLoadContainer"
    storage_container = "StorageContainer"
    generic_container = "GenericContainer"


class WorkloadType(str, Enum):

    invalid = "Invalid"
    vm = "VM"
    file_folder = "FileFolder"
    azure_sql_db = "AzureSqlDb"
    sqldb = "SQLDB"
    exchange = "Exchange"
    sharepoint = "Sharepoint"
    vmware_vm = "VMwareVM"
    system_state = "SystemState"
    client = "Client"
    generic_data_source = "GenericDataSource"
    sql_data_base = "SQLDataBase"
    azure_file_share = "AzureFileShare"
    sap_hana_database = "SAPHanaDatabase"
    sap_ase_database = "SAPAseDatabase"


class HttpStatusCode(str, Enum):

    continue_enum = "Continue"
    switching_protocols = "SwitchingProtocols"
    ok = "OK"
    created = "Created"
    accepted = "Accepted"
    non_authoritative_information = "NonAuthoritativeInformation"
    no_content = "NoContent"
    reset_content = "ResetContent"
    partial_content = "PartialContent"
    multiple_choices = "MultipleChoices"
    ambiguous = "Ambiguous"
    moved_permanently = "MovedPermanently"
    moved = "Moved"
    found = "Found"
    redirect = "Redirect"
    see_other = "SeeOther"
    redirect_method = "RedirectMethod"
    not_modified = "NotModified"
    use_proxy = "UseProxy"
    unused = "Unused"
    temporary_redirect = "TemporaryRedirect"
    redirect_keep_verb = "RedirectKeepVerb"
    bad_request = "BadRequest"
    unauthorized = "Unauthorized"
    payment_required = "PaymentRequired"
    forbidden = "Forbidden"
    not_found = "NotFound"
    method_not_allowed = "MethodNotAllowed"
    not_acceptable = "NotAcceptable"
    proxy_authentication_required = "ProxyAuthenticationRequired"
    request_timeout = "RequestTimeout"
    conflict = "Conflict"
    gone = "Gone"
    length_required = "LengthRequired"
    precondition_failed = "PreconditionFailed"
    request_entity_too_large = "RequestEntityTooLarge"
    request_uri_too_long = "RequestUriTooLong"
    unsupported_media_type = "UnsupportedMediaType"
    requested_range_not_satisfiable = "RequestedRangeNotSatisfiable"
    expectation_failed = "ExpectationFailed"
    upgrade_required = "UpgradeRequired"
    internal_server_error = "InternalServerError"
    not_implemented = "NotImplemented"
    bad_gateway = "BadGateway"
    service_unavailable = "ServiceUnavailable"
    gateway_timeout = "GatewayTimeout"
    http_version_not_supported = "HttpVersionNotSupported"


class DataSourceType(str, Enum):

    invalid = "Invalid"
    vm = "VM"
    file_folder = "FileFolder"
    azure_sql_db = "AzureSqlDb"
    sqldb = "SQLDB"
    exchange = "Exchange"
    sharepoint = "Sharepoint"
    vmware_vm = "VMwareVM"
    system_state = "SystemState"
    client = "Client"
    generic_data_source = "GenericDataSource"
    sql_data_base = "SQLDataBase"
    azure_file_share = "AzureFileShare"
    sap_hana_database = "SAPHanaDatabase"
    sap_ase_database = "SAPAseDatabase"


class CreateMode(str, Enum):

    invalid = "Invalid"
    default = "Default"
    recover = "Recover"


class HealthState(str, Enum):

    passed = "Passed"
    action_required = "ActionRequired"
    action_suggested = "ActionSuggested"
    invalid = "Invalid"


class SupportStatus(str, Enum):

    invalid = "Invalid"
    supported = "Supported"
    default_off = "DefaultOFF"
    default_on = "DefaultON"
    not_supported = "NotSupported"


class PolicyType(str, Enum):

    invalid = "Invalid"
    full = "Full"
    differential = "Differential"
    log = "Log"
    copy_only_full = "CopyOnlyFull"


class WorkloadItemType(str, Enum):

    invalid = "Invalid"
    sql_instance = "SQLInstance"
    sql_data_base = "SQLDataBase"
    sap_hana_system = "SAPHanaSystem"
    sap_hana_database = "SAPHanaDatabase"
    sap_ase_system = "SAPAseSystem"
    sap_ase_database = "SAPAseDatabase"


class UsagesUnit(str, Enum):

    count = "Count"
    bytes = "Bytes"
    seconds = "Seconds"
    percent = "Percent"
    count_per_second = "CountPerSecond"
    bytes_per_second = "BytesPerSecond"


class ProtectionStatus(str, Enum):

    invalid = "Invalid"
    not_protected = "NotProtected"
    protecting = "Protecting"
    protected = "Protected"
    protection_failed = "ProtectionFailed"


class FabricName(str, Enum):

    invalid = "Invalid"
    azure = "Azure"


class Type(str, Enum):

    invalid = "Invalid"
    backup_protected_item_count_summary = "BackupProtectedItemCountSummary"
    backup_protection_container_count_summary = "BackupProtectionContainerCountSummary"


class RetentionDurationType(str, Enum):

    invalid = "Invalid"
    days = "Days"
    weeks = "Weeks"
    months = "Months"
    years = "Years"


class DayOfWeek(str, Enum):

    sunday = "Sunday"
    monday = "Monday"
    tuesday = "Tuesday"
    wednesday = "Wednesday"
    thursday = "Thursday"
    friday = "Friday"
    saturday = "Saturday"


class RetentionScheduleFormat(str, Enum):

    invalid = "Invalid"
    daily = "Daily"
    weekly = "Weekly"


class WeekOfMonth(str, Enum):

    first = "First"
    second = "Second"
    third = "Third"
    fourth = "Fourth"
    last = "Last"
    invalid = "Invalid"


class MonthOfYear(str, Enum):

    invalid = "Invalid"
    january = "January"
    february = "February"
    march = "March"
    april = "April"
    may = "May"
    june = "June"
    july = "July"
    august = "August"
    september = "September"
    october = "October"
    november = "November"
    december = "December"


class ValidationStatus(str, Enum):

    invalid = "Invalid"
    succeeded = "Succeeded"
    failed = "Failed"


class IntentItemType(str, Enum):

    invalid = "Invalid"
    sql_instance = "SQLInstance"
    sql_availability_group_container = "SQLAvailabilityGroupContainer"


class ScheduleRunType(str, Enum):

    invalid = "Invalid"
    daily = "Daily"
    weekly = "Weekly"


class AzureFileShareType(str, Enum):

    invalid = "Invalid"
    xsmb = "XSMB"
    xsync = "XSync"


class InquiryStatus(str, Enum):

    invalid = "Invalid"
    success = "Success"
    failed = "Failed"


class BackupType(str, Enum):

    invalid = "Invalid"
    full = "Full"
    differential = "Differential"
    log = "Log"
    copy_only_full = "CopyOnlyFull"


class OperationType(str, Enum):

    invalid = "Invalid"
    register = "Register"
    reregister = "Reregister"


class ContainerType(str, Enum):

    invalid = "Invalid"
    unknown = "Unknown"
    iaas_vm_container = "IaasVMContainer"
    iaas_vm_service_container = "IaasVMServiceContainer"
    dpm_container = "DPMContainer"
    azure_backup_server_container = "AzureBackupServerContainer"
    mab_container = "MABContainer"
    cluster = "Cluster"
    azure_sql_container = "AzureSqlContainer"
    windows = "Windows"
    vcenter = "VCenter"
    vm_app_container = "VMAppContainer"
    sqlag_work_load_container = "SQLAGWorkLoadContainer"
    storage_container = "StorageContainer"
    generic_container = "GenericContainer"


class BackupItemType(str, Enum):

    invalid = "Invalid"
    vm = "VM"
    file_folder = "FileFolder"
    azure_sql_db = "AzureSqlDb"
    sqldb = "SQLDB"
    exchange = "Exchange"
    sharepoint = "Sharepoint"
    vmware_vm = "VMwareVM"
    system_state = "SystemState"
    client = "Client"
    generic_data_source = "GenericDataSource"
    sql_data_base = "SQLDataBase"
    azure_file_share = "AzureFileShare"
    sap_hana_database = "SAPHanaDatabase"
    sap_ase_database = "SAPAseDatabase"


class OperationStatusValues(str, Enum):

    invalid = "Invalid"
    in_progress = "InProgress"
    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"
