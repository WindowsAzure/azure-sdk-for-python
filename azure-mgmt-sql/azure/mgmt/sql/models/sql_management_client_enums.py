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


class BackupLongTermRetentionPolicyState(Enum):

    disabled = "Disabled"
    enabled = "Enabled"


class RestorePointType(Enum):

    discrete = "DISCRETE"
    continuous = "CONTINUOUS"


class CapabilityStatus(Enum):

    visible = "Visible"
    available = "Available"
    default = "Default"
    disabled = "Disabled"


class MaxSizeUnits(Enum):

    megabytes = "Megabytes"
    gigabytes = "Gigabytes"
    terabytes = "Terabytes"
    petabytes = "Petabytes"


class PerformanceLevelUnit(Enum):

    dtu = "DTU"


class ServerConnectionType(Enum):

    default = "Default"
    proxy = "Proxy"
    redirect = "Redirect"


class SecurityAlertPolicyState(Enum):

    new = "New"
    enabled = "Enabled"
    disabled = "Disabled"


class SecurityAlertPolicyEmailAccountAdmins(Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class SecurityAlertPolicyUseServerDefault(Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class DataMaskingState(Enum):

    disabled = "Disabled"
    enabled = "Enabled"


class DataMaskingRuleState(Enum):

    disabled = "Disabled"
    enabled = "Enabled"


class DataMaskingFunction(Enum):

    default = "Default"
    ccn = "CCN"
    email = "Email"
    number = "Number"
    ssn = "SSN"
    text = "Text"


class GeoBackupPolicyState(Enum):

    disabled = "Disabled"
    enabled = "Enabled"


class DatabaseEdition(Enum):

    web = "Web"
    business = "Business"
    basic = "Basic"
    standard = "Standard"
    premium = "Premium"
    free = "Free"
    stretch = "Stretch"
    data_warehouse = "DataWarehouse"
    system = "System"
    system2 = "System2"


class ServiceObjectiveName(Enum):

    basic = "Basic"
    s0 = "S0"
    s1 = "S1"
    s2 = "S2"
    s3 = "S3"
    p1 = "P1"
    p2 = "P2"
    p3 = "P3"
    p4 = "P4"
    p6 = "P6"
    p11 = "P11"
    p15 = "P15"
    system = "System"
    system2 = "System2"
    elastic_pool = "ElasticPool"


class StorageKeyType(Enum):

    storage_access_key = "StorageAccessKey"
    shared_access_key = "SharedAccessKey"


class AuthenticationType(Enum):

    sql = "SQL"
    ad_password = "ADPassword"


class UnitType(Enum):

    count = "count"
    bytes = "bytes"
    seconds = "seconds"
    percent = "percent"
    count_per_second = "countPerSecond"
    bytes_per_second = "bytesPerSecond"


class PrimaryAggregationType(Enum):

    none = "None"
    average = "Average"
    count = "Count"
    minimum = "Minimum"
    maximum = "Maximum"
    total = "Total"


class UnitDefinitionType(Enum):

    count = "Count"
    bytes = "Bytes"
    seconds = "Seconds"
    percent = "Percent"
    count_per_second = "CountPerSecond"
    bytes_per_second = "BytesPerSecond"


class ReplicationRole(Enum):

    primary = "Primary"
    secondary = "Secondary"
    non_readable_secondary = "NonReadableSecondary"
    source = "Source"
    copy = "Copy"


class ReplicationState(Enum):

    pending = "PENDING"
    seeding = "SEEDING"
    catch_up = "CATCH_UP"
    suspended = "SUSPENDED"


class CheckNameAvailabilityReason(Enum):

    invalid = "Invalid"
    already_exists = "AlreadyExists"


class ElasticPoolEdition(Enum):

    basic = "Basic"
    standard = "Standard"
    premium = "Premium"


class CreateMode(Enum):

    copy = "Copy"
    default = "Default"
    non_readable_secondary = "NonReadableSecondary"
    online_secondary = "OnlineSecondary"
    point_in_time_restore = "PointInTimeRestore"
    recovery = "Recovery"
    restore = "Restore"
    restore_long_term_retention_backup = "RestoreLongTermRetentionBackup"


class TransparentDataEncryptionStatus(Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class RecommendedIndexAction(Enum):

    create = "Create"
    drop = "Drop"
    rebuild = "Rebuild"


class RecommendedIndexState(Enum):

    active = "Active"
    pending = "Pending"
    executing = "Executing"
    verifying = "Verifying"
    pending_revert = "Pending Revert"
    reverting = "Reverting"
    reverted = "Reverted"
    ignored = "Ignored"
    expired = "Expired"
    blocked = "Blocked"
    success = "Success"


class RecommendedIndexType(Enum):

    clustered = "CLUSTERED"
    nonclustered = "NONCLUSTERED"
    columnstore = "COLUMNSTORE"
    clusteredcolumnstore = "CLUSTERED COLUMNSTORE"


class ReadScale(Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class SampleName(Enum):

    adventure_works_lt = "AdventureWorksLT"


class ElasticPoolState(Enum):

    creating = "Creating"
    ready = "Ready"
    disabled = "Disabled"


class TransparentDataEncryptionActivityStatus(Enum):

    encrypting = "Encrypting"
    decrypting = "Decrypting"


class BlobAuditingPolicyState(Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class ServerKeyType(Enum):

    service_managed = "ServiceManaged"
    azure_key_vault = "AzureKeyVault"


class ReadWriteEndpointFailoverPolicy(Enum):

    manual = "Manual"
    automatic = "Automatic"


class ReadOnlyEndpointFailoverPolicy(Enum):

    disabled = "Disabled"
    enabled = "Enabled"


class FailoverGroupReplicationRole(Enum):

    primary = "Primary"
    secondary = "Secondary"


class IdentityType(Enum):

    system_assigned = "SystemAssigned"
