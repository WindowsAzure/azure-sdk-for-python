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


class KeyVaultSecretStatus(Enum):

    initialized = "Initialized"
    waiting_on_certificate_order = "WaitingOnCertificateOrder"
    succeeded = "Succeeded"
    certificate_order_failed = "CertificateOrderFailed"
    operation_not_permitted_on_key_vault = "OperationNotPermittedOnKeyVault"
    azure_service_unauthorized_to_access_key_vault = "AzureServiceUnauthorizedToAccessKeyVault"
    key_vault_does_not_exist = "KeyVaultDoesNotExist"
    key_vault_secret_does_not_exist = "KeyVaultSecretDoesNotExist"
    unknown_error = "UnknownError"
    external_private_key = "ExternalPrivateKey"
    unknown = "Unknown"


class CertificateProductType(Enum):

    standard_domain_validated_ssl = "StandardDomainValidatedSsl"
    standard_domain_validated_wild_card_ssl = "StandardDomainValidatedWildCardSsl"


class ProvisioningState(Enum):

    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"
    in_progress = "InProgress"
    deleting = "Deleting"


class CertificateOrderStatus(Enum):

    pendingissuance = "Pendingissuance"
    issued = "Issued"
    revoked = "Revoked"
    canceled = "Canceled"
    denied = "Denied"
    pendingrevocation = "Pendingrevocation"
    pending_rekey = "PendingRekey"
    unused = "Unused"
    expired = "Expired"
    not_submitted = "NotSubmitted"


class CertificateOrderActionType(Enum):

    certificate_issued = "CertificateIssued"
    certificate_order_canceled = "CertificateOrderCanceled"
    certificate_order_created = "CertificateOrderCreated"
    certificate_revoked = "CertificateRevoked"
    domain_validation_complete = "DomainValidationComplete"
    fraud_detected = "FraudDetected"
    org_name_change = "OrgNameChange"
    org_validation_complete = "OrgValidationComplete"
    san_drop = "SanDrop"
    fraud_cleared = "FraudCleared"
    certificate_expired = "CertificateExpired"
    certificate_expiration_warning = "CertificateExpirationWarning"
    fraud_documentation_required = "FraudDocumentationRequired"
    unknown = "Unknown"


class RouteType(Enum):

    default = "DEFAULT"
    inherited = "INHERITED"
    static = "STATIC"


class AutoHealActionType(Enum):

    recycle = "Recycle"
    log_event = "LogEvent"
    custom_action = "CustomAction"


class ConnectionStringType(Enum):

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


class ScmType(Enum):

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


class ManagedPipelineMode(Enum):

    integrated = "Integrated"
    classic = "Classic"


class SiteLoadBalancing(Enum):

    weighted_round_robin = "WeightedRoundRobin"
    least_requests = "LeastRequests"
    least_response_time = "LeastResponseTime"
    weighted_total_traffic = "WeightedTotalTraffic"
    request_hash = "RequestHash"


class SslState(Enum):

    disabled = "Disabled"
    sni_enabled = "SniEnabled"
    ip_based_enabled = "IpBasedEnabled"


class HostType(Enum):

    standard = "Standard"
    repository = "Repository"


class UsageState(Enum):

    normal = "Normal"
    exceeded = "Exceeded"


class SiteAvailabilityState(Enum):

    normal = "Normal"
    limited = "Limited"
    disaster_recovery_mode = "DisasterRecoveryMode"


class StatusOptions(Enum):

    ready = "Ready"
    pending = "Pending"
    creating = "Creating"


class DomainStatus(Enum):

    active = "Active"
    awaiting = "Awaiting"
    cancelled = "Cancelled"
    confiscated = "Confiscated"
    disabled = "Disabled"
    excluded = "Excluded"
    expired = "Expired"
    failed = "Failed"
    held = "Held"
    locked = "Locked"
    parked = "Parked"
    pending = "Pending"
    reserved = "Reserved"
    reverted = "Reverted"
    suspended = "Suspended"
    transferred = "Transferred"
    unknown = "Unknown"
    unlocked = "Unlocked"
    unparked = "Unparked"
    updated = "Updated"
    json_converter_failed = "JsonConverterFailed"


class AzureResourceType(Enum):

    website = "Website"
    traffic_manager = "TrafficManager"


class CustomHostNameDnsRecordType(Enum):

    cname = "CName"
    a = "A"


class HostNameType(Enum):

    verified = "Verified"
    managed = "Managed"


class DnsType(Enum):

    azure_dns = "AzureDns"
    default_domain_registrar_dns = "DefaultDomainRegistrarDns"


class DomainType(Enum):

    regular = "Regular"
    soft_deleted = "SoftDeleted"


class HostingEnvironmentStatus(Enum):

    preparing = "Preparing"
    ready = "Ready"
    scaling = "Scaling"
    deleting = "Deleting"


class InternalLoadBalancingMode(Enum):

    none = "None"
    web = "Web"
    publishing = "Publishing"


class ComputeModeOptions(Enum):

    shared = "Shared"
    dedicated = "Dedicated"
    dynamic = "Dynamic"


class WorkerSizeOptions(Enum):

    default = "Default"
    small = "Small"
    medium = "Medium"
    large = "Large"
    d1 = "D1"
    d2 = "D2"
    d3 = "D3"


class AccessControlEntryAction(Enum):

    permit = "Permit"
    deny = "Deny"


class OperationStatus(Enum):

    in_progress = "InProgress"
    failed = "Failed"
    succeeded = "Succeeded"
    timed_out = "TimedOut"
    created = "Created"


class IssueType(Enum):

    service_incident = "ServiceIncident"
    app_deployment = "AppDeployment"
    app_crash = "AppCrash"
    runtime_issue_detected = "RuntimeIssueDetected"
    ase_deployment = "AseDeployment"
    user_issue = "UserIssue"
    platform_issue = "PlatformIssue"
    other = "Other"


class SolutionType(Enum):

    quick_solution = "QuickSolution"
    deep_investigation = "DeepInvestigation"
    best_practices = "BestPractices"


class ResourceScopeType(Enum):

    server_farm = "ServerFarm"
    subscription = "Subscription"
    web_site = "WebSite"


class NotificationLevel(Enum):

    critical = "Critical"
    warning = "Warning"
    information = "Information"
    non_urgent_suggestion = "NonUrgentSuggestion"


class Channels(Enum):

    notification = "Notification"
    api = "Api"
    email = "Email"
    webhook = "Webhook"
    all = "All"


class AppServicePlanRestrictions(Enum):

    none = "None"
    free = "Free"
    shared = "Shared"
    basic = "Basic"
    standard = "Standard"
    premium = "Premium"


class InAvailabilityReasonType(Enum):

    invalid = "Invalid"
    already_exists = "AlreadyExists"


class CheckNameResourceTypes(Enum):

    site = "Site"
    slot = "Slot"
    hosting_environment = "HostingEnvironment"
    publishing_user = "PublishingUser"
    microsoft_websites = "Microsoft.Web/sites"
    microsoft_websitesslots = "Microsoft.Web/sites/slots"
    microsoft_webhosting_environments = "Microsoft.Web/hostingEnvironments"
    microsoft_webpublishing_users = "Microsoft.Web/publishingUsers"


class ValidateResourceTypes(Enum):

    server_farm = "ServerFarm"
    site = "Site"


class LogLevel(Enum):

    off = "Off"
    verbose = "Verbose"
    information = "Information"
    warning = "Warning"
    error = "Error"


class BackupItemStatus(Enum):

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


class DatabaseType(Enum):

    sql_azure = "SqlAzure"
    my_sql = "MySql"
    local_my_sql = "LocalMySql"
    postgre_sql = "PostgreSql"


class FrequencyUnit(Enum):

    day = "Day"
    hour = "Hour"


class ContinuousWebJobStatus(Enum):

    initializing = "Initializing"
    starting = "Starting"
    running = "Running"
    pending_restart = "PendingRestart"
    stopped = "Stopped"


class WebJobType(Enum):

    continuous = "Continuous"
    triggered = "Triggered"


class PublishingProfileFormat(Enum):

    file_zilla3 = "FileZilla3"
    web_deploy = "WebDeploy"
    ftp = "Ftp"


class DnsVerificationTestResult(Enum):

    passed = "Passed"
    failed = "Failed"
    skipped = "Skipped"


class MSDeployLogEntryType(Enum):

    message = "Message"
    warning = "Warning"
    error = "Error"


class MSDeployProvisioningState(Enum):

    accepted = "accepted"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    canceled = "canceled"


class MySqlMigrationType(Enum):

    local_to_remote = "LocalToRemote"
    remote_to_local = "RemoteToLocal"


class PublicCertificateLocation(Enum):

    current_user_my = "CurrentUserMy"
    local_machine_my = "LocalMachineMy"
    unknown = "Unknown"


class BackupRestoreOperationType(Enum):

    default = "Default"
    clone = "Clone"
    relocation = "Relocation"
    snapshot = "Snapshot"


class UnauthenticatedClientAction(Enum):

    redirect_to_login_page = "RedirectToLoginPage"
    allow_anonymous = "AllowAnonymous"


class BuiltInAuthenticationProvider(Enum):

    azure_active_directory = "AzureActiveDirectory"
    facebook = "Facebook"
    google = "Google"
    microsoft_account = "MicrosoftAccount"
    twitter = "Twitter"


class CloneAbilityResult(Enum):

    cloneable = "Cloneable"
    partially_cloneable = "PartiallyCloneable"
    not_cloneable = "NotCloneable"


class SiteExtensionType(Enum):

    gallery = "Gallery"
    web_root = "WebRoot"


class TriggeredWebJobStatus(Enum):

    success = "Success"
    failed = "Failed"
    error = "Error"


class SkuName(Enum):

    free = "Free"
    shared = "Shared"
    basic = "Basic"
    standard = "Standard"
    premium = "Premium"
    premium_v2 = "PremiumV2"
    dynamic = "Dynamic"
    isolated = "Isolated"
