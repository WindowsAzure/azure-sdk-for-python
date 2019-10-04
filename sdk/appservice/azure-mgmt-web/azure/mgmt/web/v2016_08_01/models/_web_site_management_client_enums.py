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


class LogLevel(str, Enum):

    off = "Off"
    verbose = "Verbose"
    information = "Information"
    warning = "Warning"
    error = "Error"


class BackupItemStatus(str, Enum):

    in_progress = "InProgress"
    failed = "Failed"
    succeeded = "Succeeded"
    timed_out = "TimedOut"
    created = "Created"
    skipped = "Skipped"
    partially_succeeded = "PartiallySucceeded"
    delete_in_progress = "DeleteInProgress"
    delete_failed = "DeleteFailed"
    deleted = "Deleted"


class DatabaseType(str, Enum):

    sql_azure = "SqlAzure"
    my_sql = "MySql"
    local_my_sql = "LocalMySql"
    postgre_sql = "PostgreSql"


class FrequencyUnit(str, Enum):

    day = "Day"
    hour = "Hour"


class BackupRestoreOperationType(str, Enum):

    default = "Default"
    clone = "Clone"
    relocation = "Relocation"
    snapshot = "Snapshot"


class ConnectionStringType(str, Enum):

    my_sql = "MySql"
    sql_server = "SQLServer"
    sql_azure = "SQLAzure"
    custom = "Custom"
    notification_hub = "NotificationHub"
    service_bus = "ServiceBus"
    event_hub = "EventHub"
    api_hub = "ApiHub"
    doc_db = "DocDb"
    redis_cache = "RedisCache"
    postgre_sql = "PostgreSQL"


class ContinuousWebJobStatus(str, Enum):

    initializing = "Initializing"
    starting = "Starting"
    running = "Running"
    pending_restart = "PendingRestart"
    stopped = "Stopped"


class WebJobType(str, Enum):

    continuous = "Continuous"
    triggered = "Triggered"


class PublishingProfileFormat(str, Enum):

    file_zilla3 = "FileZilla3"
    web_deploy = "WebDeploy"
    ftp = "Ftp"


class DnsVerificationTestResult(str, Enum):

    passed = "Passed"
    failed = "Failed"
    skipped = "Skipped"


class AzureResourceType(str, Enum):

    website = "Website"
    traffic_manager = "TrafficManager"


class CustomHostNameDnsRecordType(str, Enum):

    cname = "CName"
    a = "A"


class HostNameType(str, Enum):

    verified = "Verified"
    managed = "Managed"


class SslState(str, Enum):

    disabled = "Disabled"
    sni_enabled = "SniEnabled"
    ip_based_enabled = "IpBasedEnabled"


class MSDeployLogEntryType(str, Enum):

    message = "Message"
    warning = "Warning"
    error = "Error"


class MSDeployProvisioningState(str, Enum):

    accepted = "accepted"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    canceled = "canceled"


class MySqlMigrationType(str, Enum):

    local_to_remote = "LocalToRemote"
    remote_to_local = "RemoteToLocal"


class OperationStatus(str, Enum):

    in_progress = "InProgress"
    failed = "Failed"
    succeeded = "Succeeded"
    timed_out = "TimedOut"
    created = "Created"


class RouteType(str, Enum):

    default = "DEFAULT"
    inherited = "INHERITED"
    static = "STATIC"


class PublicCertificateLocation(str, Enum):

    current_user_my = "CurrentUserMy"
    local_machine_my = "LocalMachineMy"
    unknown = "Unknown"


class UnauthenticatedClientAction(str, Enum):

    redirect_to_login_page = "RedirectToLoginPage"
    allow_anonymous = "AllowAnonymous"


class BuiltInAuthenticationProvider(str, Enum):

    azure_active_directory = "AzureActiveDirectory"
    facebook = "Facebook"
    google = "Google"
    microsoft_account = "MicrosoftAccount"
    twitter = "Twitter"


class CloneAbilityResult(str, Enum):

    cloneable = "Cloneable"
    partially_cloneable = "PartiallyCloneable"
    not_cloneable = "NotCloneable"


class ScmType(str, Enum):

    none = "None"
    dropbox = "Dropbox"
    tfs = "Tfs"
    local_git = "LocalGit"
    git_hub = "GitHub"
    code_plex_git = "CodePlexGit"
    code_plex_hg = "CodePlexHg"
    bitbucket_git = "BitbucketGit"
    bitbucket_hg = "BitbucketHg"
    external_git = "ExternalGit"
    external_hg = "ExternalHg"
    one_drive = "OneDrive"
    vso = "VSO"


class ManagedPipelineMode(str, Enum):

    integrated = "Integrated"
    classic = "Classic"


class SiteLoadBalancing(str, Enum):

    weighted_round_robin = "WeightedRoundRobin"
    least_requests = "LeastRequests"
    least_response_time = "LeastResponseTime"
    weighted_total_traffic = "WeightedTotalTraffic"
    request_hash = "RequestHash"


class AutoHealActionType(str, Enum):

    recycle = "Recycle"
    log_event = "LogEvent"
    custom_action = "CustomAction"


class SupportedTlsVersions(str, Enum):

    one_full_stop_zero = "1.0"
    one_full_stop_one = "1.1"
    one_full_stop_two = "1.2"


class SiteExtensionType(str, Enum):

    gallery = "Gallery"
    web_root = "WebRoot"


class UsageState(str, Enum):

    normal = "Normal"
    exceeded = "Exceeded"


class SiteAvailabilityState(str, Enum):

    normal = "Normal"
    limited = "Limited"
    disaster_recovery_mode = "DisasterRecoveryMode"


class HostType(str, Enum):

    standard = "Standard"
    repository = "Repository"


class TriggeredWebJobStatus(str, Enum):

    success = "Success"
    failed = "Failed"
    error = "Error"


class ManagedServiceIdentityType(str, Enum):

    system_assigned = "SystemAssigned"


class StatusOptions(str, Enum):

    ready = "Ready"
    pending = "Pending"
    creating = "Creating"


class ProvisioningState(str, Enum):

    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"
    in_progress = "InProgress"
    deleting = "Deleting"
