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


class CommandState(str, Enum):

    unknown = "Unknown"
    accepted = "Accepted"
    running = "Running"
    succeeded = "Succeeded"
    failed = "Failed"


class SqlSourcePlatform(str, Enum):

    sql_on_prem = "SqlOnPrem"


class AuthenticationType(str, Enum):

    none = "None"
    windows_authentication = "WindowsAuthentication"
    sql_authentication = "SqlAuthentication"
    active_directory_integrated = "ActiveDirectoryIntegrated"
    active_directory_password = "ActiveDirectoryPassword"


class MongoDbErrorType(str, Enum):

    error = "Error"
    validation_error = "ValidationError"
    warning = "Warning"


class MongoDbMigrationState(str, Enum):

    not_started = "NotStarted"
    validating_input = "ValidatingInput"
    initializing = "Initializing"
    restarting = "Restarting"
    copying = "Copying"
    initial_replay = "InitialReplay"
    replaying = "Replaying"
    finalizing = "Finalizing"
    complete = "Complete"
    canceled = "Canceled"
    failed = "Failed"


class MongoDbShardKeyOrder(str, Enum):

    forward = "Forward"
    reverse = "Reverse"
    hashed = "Hashed"


class MongoDbReplication(str, Enum):

    disabled = "Disabled"
    one_time = "OneTime"
    continuous = "Continuous"


class BackupType(str, Enum):

    database = "Database"
    transaction_log = "TransactionLog"
    file = "File"
    differential_database = "DifferentialDatabase"
    differential_file = "DifferentialFile"
    partial = "Partial"
    differential_partial = "DifferentialPartial"


class BackupMode(str, Enum):

    create_backup = "CreateBackup"
    existing_backup = "ExistingBackup"


class SyncTableMigrationState(str, Enum):

    before_load = "BEFORE_LOAD"
    full_load = "FULL_LOAD"
    completed = "COMPLETED"
    canceled = "CANCELED"
    error = "ERROR"
    failed = "FAILED"


class SyncDatabaseMigrationReportingState(str, Enum):

    undefined = "UNDEFINED"
    configuring = "CONFIGURING"
    initialiazing = "INITIALIAZING"
    starting = "STARTING"
    running = "RUNNING"
    ready_to_complete = "READY_TO_COMPLETE"
    completing = "COMPLETING"
    complete = "COMPLETE"
    cancelling = "CANCELLING"
    cancelled = "CANCELLED"
    failed = "FAILED"


class ValidationStatus(str, Enum):

    default = "Default"
    not_started = "NotStarted"
    initialized = "Initialized"
    in_progress = "InProgress"
    completed = "Completed"
    completed_with_issues = "CompletedWithIssues"
    stopped = "Stopped"
    failed = "Failed"


class Severity(str, Enum):

    message = "Message"
    warning = "Warning"
    error = "Error"


class UpdateActionType(str, Enum):

    deleted_on_target = "DeletedOnTarget"
    changed_on_target = "ChangedOnTarget"
    added_on_target = "AddedOnTarget"


class ObjectType(str, Enum):

    stored_procedures = "StoredProcedures"
    table = "Table"
    user = "User"
    view = "View"
    function = "Function"


class MigrationState(str, Enum):

    none = "None"
    in_progress = "InProgress"
    failed = "Failed"
    warning = "Warning"
    completed = "Completed"
    skipped = "Skipped"
    stopped = "Stopped"


class DatabaseMigrationStage(str, Enum):

    none = "None"
    initialize = "Initialize"
    backup = "Backup"
    file_copy = "FileCopy"
    restore = "Restore"
    completed = "Completed"


class MigrationStatus(str, Enum):

    default = "Default"
    connecting = "Connecting"
    source_and_target_selected = "SourceAndTargetSelected"
    select_logins = "SelectLogins"
    configured = "Configured"
    running = "Running"
    error = "Error"
    stopped = "Stopped"
    completed = "Completed"
    completed_with_warnings = "CompletedWithWarnings"


class LoginMigrationStage(str, Enum):

    none = "None"
    initialize = "Initialize"
    login_migration = "LoginMigration"
    establish_user_mapping = "EstablishUserMapping"
    assign_role_membership = "AssignRoleMembership"
    assign_role_ownership = "AssignRoleOwnership"
    establish_server_permissions = "EstablishServerPermissions"
    establish_object_permissions = "EstablishObjectPermissions"
    completed = "Completed"


class LoginType(str, Enum):

    windows_user = "WindowsUser"
    windows_group = "WindowsGroup"
    sql_login = "SqlLogin"
    certificate = "Certificate"
    asymmetric_key = "AsymmetricKey"
    external_user = "ExternalUser"
    external_group = "ExternalGroup"


class DatabaseState(str, Enum):

    online = "Online"
    restoring = "Restoring"
    recovering = "Recovering"
    recovery_pending = "RecoveryPending"
    suspect = "Suspect"
    emergency = "Emergency"
    offline = "Offline"
    copying = "Copying"
    offline_secondary = "OfflineSecondary"


class DatabaseCompatLevel(str, Enum):

    compat_level80 = "CompatLevel80"
    compat_level90 = "CompatLevel90"
    compat_level100 = "CompatLevel100"
    compat_level110 = "CompatLevel110"
    compat_level120 = "CompatLevel120"
    compat_level130 = "CompatLevel130"
    compat_level140 = "CompatLevel140"


class DatabaseFileType(str, Enum):

    rows = "Rows"
    log = "Log"
    filestream = "Filestream"
    not_supported = "NotSupported"
    fulltext = "Fulltext"


class ServerLevelPermissionsGroup(str, Enum):

    default = "Default"
    migration_from_sql_server_to_azure_db = "MigrationFromSqlServerToAzureDB"
    migration_from_sql_server_to_azure_mi = "MigrationFromSqlServerToAzureMI"
    migration_from_my_sql_to_azure_db_for_my_sql = "MigrationFromMySQLToAzureDBForMySQL"


class MongoDbClusterType(str, Enum):

    blob_container = "BlobContainer"
    cosmos_db = "CosmosDb"
    mongo_db = "MongoDb"


class TaskState(str, Enum):

    unknown = "Unknown"
    queued = "Queued"
    running = "Running"
    canceled = "Canceled"
    succeeded = "Succeeded"
    failed = "Failed"
    failed_input_validation = "FailedInputValidation"
    faulted = "Faulted"


class ServiceProvisioningState(str, Enum):

    accepted = "Accepted"
    deleting = "Deleting"
    deploying = "Deploying"
    stopped = "Stopped"
    stopping = "Stopping"
    starting = "Starting"
    failed_to_start = "FailedToStart"
    failed_to_stop = "FailedToStop"
    succeeded = "Succeeded"
    failed = "Failed"


class ProjectTargetPlatform(str, Enum):

    sqldb = "SQLDB"
    sqlmi = "SQLMI"
    azure_db_for_my_sql = "AzureDbForMySql"
    azure_db_for_postgre_sql = "AzureDbForPostgreSql"
    mongo_db = "MongoDb"
    unknown = "Unknown"


class ProjectSourcePlatform(str, Enum):

    sql = "SQL"
    my_sql = "MySQL"
    postgre_sql = "PostgreSql"
    mongo_db = "MongoDb"
    unknown = "Unknown"


class ProjectProvisioningState(str, Enum):

    deleting = "Deleting"
    succeeded = "Succeeded"


class NameCheckFailureReason(str, Enum):

    already_exists = "AlreadyExists"
    invalid = "Invalid"


class ServiceScalability(str, Enum):

    none = "none"
    manual = "manual"
    automatic = "automatic"


class ResourceSkuRestrictionsType(str, Enum):

    location = "location"


class ResourceSkuRestrictionsReasonCode(str, Enum):

    quota_id = "QuotaId"
    not_available_for_subscription = "NotAvailableForSubscription"


class ResourceSkuCapacityScaleType(str, Enum):

    automatic = "Automatic"
    manual = "Manual"
    none = "None"


class MySqlTargetPlatformType(str, Enum):

    azure_db_for_my_sql = "AzureDbForMySQL"


class SchemaMigrationOption(str, Enum):

    none = "None"
    extract_from_source = "ExtractFromSource"
    use_storage_file = "UseStorageFile"


class SchemaMigrationStage(str, Enum):

    not_started = "NotStarted"
    validating_inputs = "ValidatingInputs"
    collecting_objects = "CollectingObjects"
    downloading_script = "DownloadingScript"
    generating_script = "GeneratingScript"
    uploading_script = "UploadingScript"
    deploying_schema = "DeployingSchema"
    completed = "Completed"
    completed_with_warnings = "CompletedWithWarnings"
    failed = "Failed"


class DataMigrationResultCode(str, Enum):

    initial = "Initial"
    completed = "Completed"
    object_not_exists_in_source = "ObjectNotExistsInSource"
    object_not_exists_in_target = "ObjectNotExistsInTarget"
    target_object_is_inaccessible = "TargetObjectIsInaccessible"
    fatal_error = "FatalError"


class ErrorType(str, Enum):

    default = "Default"
    warning = "Warning"
    error = "Error"
