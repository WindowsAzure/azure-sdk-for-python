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


class KeyVaultSecretStatus(str, Enum):

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


class RouteType(str, Enum):

    default = "DEFAULT"
    inherited = "INHERITED"
    static = "STATIC"


class ManagedServiceIdentityType(str, Enum):

    system_assigned = "SystemAssigned"


class AutoHealActionType(str, Enum):

    recycle = "Recycle"
    log_event = "LogEvent"
    custom_action = "CustomAction"


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


class SupportedTlsVersions(str, Enum):

    one_full_stop_zero = "1.0"
    one_full_stop_one = "1.1"
    one_full_stop_two = "1.2"


class SslState(str, Enum):

    disabled = "Disabled"
    sni_enabled = "SniEnabled"
    ip_based_enabled = "IpBasedEnabled"


class HostType(str, Enum):

    standard = "Standard"
    repository = "Repository"


class UsageState(str, Enum):

    normal = "Normal"
    exceeded = "Exceeded"


class SiteAvailabilityState(str, Enum):

    normal = "Normal"
    limited = "Limited"
    disaster_recovery_mode = "DisasterRecoveryMode"


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


class HostingEnvironmentStatus(str, Enum):

    preparing = "Preparing"
    ready = "Ready"
    scaling = "Scaling"
    deleting = "Deleting"


class InternalLoadBalancingMode(str, Enum):

    none = "None"
    web = "Web"
    publishing = "Publishing"


class ComputeModeOptions(str, Enum):

    shared = "Shared"
    dedicated = "Dedicated"
    dynamic = "Dynamic"


class WorkerSizeOptions(str, Enum):

    default = "Default"
    small = "Small"
    medium = "Medium"
    large = "Large"
    d1 = "D1"
    d2 = "D2"
    d3 = "D3"


class AccessControlEntryAction(str, Enum):

    permit = "Permit"
    deny = "Deny"


class OperationStatus(str, Enum):

    in_progress = "InProgress"
    failed = "Failed"
    succeeded = "Succeeded"
    timed_out = "TimedOut"
    created = "Created"


class IssueType(str, Enum):

    service_incident = "ServiceIncident"
    app_deployment = "AppDeployment"
    app_crash = "AppCrash"
    runtime_issue_detected = "RuntimeIssueDetected"
    ase_deployment = "AseDeployment"
    user_issue = "UserIssue"
    platform_issue = "PlatformIssue"
    other = "Other"


class SolutionType(str, Enum):

    quick_solution = "QuickSolution"
    deep_investigation = "DeepInvestigation"
    best_practices = "BestPractices"


class RenderingType(str, Enum):

    no_graph = "NoGraph"
    table = "Table"
    time_series = "TimeSeries"
    time_series_per_instance = "TimeSeriesPerInstance"


class ResourceScopeType(str, Enum):

    server_farm = "ServerFarm"
    subscription = "Subscription"
    web_site = "WebSite"


class NotificationLevel(str, Enum):

    critical = "Critical"
    warning = "Warning"
    information = "Information"
    non_urgent_suggestion = "NonUrgentSuggestion"


class Channels(str, Enum):

    notification = "Notification"
    api = "Api"
    email = "Email"
    webhook = "Webhook"
    all = "All"


class AppServicePlanRestrictions(str, Enum):

    none = "None"
    free = "Free"
    shared = "Shared"
    basic = "Basic"
    standard = "Standard"
    premium = "Premium"


class InAvailabilityReasonType(str, Enum):

    invalid = "Invalid"
    already_exists = "AlreadyExists"


class CheckNameResourceTypes(str, Enum):

    site = "Site"
    slot = "Slot"
    hosting_environment = "HostingEnvironment"
    publishing_user = "PublishingUser"
    microsoft_websites = "Microsoft.Web/sites"
    microsoft_websitesslots = "Microsoft.Web/sites/slots"
    microsoft_webhosting_environments = "Microsoft.Web/hostingEnvironments"
    microsoft_webpublishing_users = "Microsoft.Web/publishingUsers"


class ValidateResourceTypes(str, Enum):

    server_farm = "ServerFarm"
    site = "Site"


class SkuName(str, Enum):

    free = "Free"
    shared = "Shared"
    basic = "Basic"
    standard = "Standard"
    premium = "Premium"
    premium_v2 = "PremiumV2"
    dynamic = "Dynamic"
    isolated = "Isolated"
