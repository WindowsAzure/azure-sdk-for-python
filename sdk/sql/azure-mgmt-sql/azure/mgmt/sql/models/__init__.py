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

try:
    from ._models_py3 import AutomaticTuningOptions
    from ._models_py3 import AutomaticTuningServerOptions
    from ._models_py3 import AutoPauseDelayTimeRange
    from ._models_py3 import BackupLongTermRetentionPolicy
    from ._models_py3 import BackupShortTermRetentionPolicy
    from ._models_py3 import CheckNameAvailabilityRequest
    from ._models_py3 import CheckNameAvailabilityResponse
    from ._models_py3 import CompleteDatabaseRestoreDefinition
    from ._models_py3 import CreateDatabaseRestorePointDefinition
    from ._models_py3 import Database
    from ._models_py3 import DatabaseAutomaticTuning
    from ._models_py3 import DatabaseBlobAuditingPolicy
    from ._models_py3 import DatabaseOperation
    from ._models_py3 import DatabaseSecurityAlertPolicy
    from ._models_py3 import DatabaseUpdate
    from ._models_py3 import DatabaseUsage
    from ._models_py3 import DatabaseVulnerabilityAssessment
    from ._models_py3 import DatabaseVulnerabilityAssessmentRuleBaseline
    from ._models_py3 import DatabaseVulnerabilityAssessmentRuleBaselineItem
    from ._models_py3 import DatabaseVulnerabilityAssessmentScansExport
    from ._models_py3 import DataMaskingPolicy
    from ._models_py3 import DataMaskingRule
    from ._models_py3 import EditionCapability
    from ._models_py3 import ElasticPool
    from ._models_py3 import ElasticPoolActivity
    from ._models_py3 import ElasticPoolDatabaseActivity
    from ._models_py3 import ElasticPoolEditionCapability
    from ._models_py3 import ElasticPoolOperation
    from ._models_py3 import ElasticPoolPerDatabaseMaxPerformanceLevelCapability
    from ._models_py3 import ElasticPoolPerDatabaseMinPerformanceLevelCapability
    from ._models_py3 import ElasticPoolPerDatabaseSettings
    from ._models_py3 import ElasticPoolPerformanceLevelCapability
    from ._models_py3 import ElasticPoolUpdate
    from ._models_py3 import EncryptionProtector
    from ._models_py3 import ExportRequest
    from ._models_py3 import ExtendedDatabaseBlobAuditingPolicy
    from ._models_py3 import ExtendedServerBlobAuditingPolicy
    from ._models_py3 import FailoverGroup
    from ._models_py3 import FailoverGroupReadOnlyEndpoint
    from ._models_py3 import FailoverGroupReadWriteEndpoint
    from ._models_py3 import FailoverGroupUpdate
    from ._models_py3 import FirewallRule
    from ._models_py3 import GeoBackupPolicy
    from ._models_py3 import ImportExportResponse
    from ._models_py3 import ImportExtensionRequest
    from ._models_py3 import ImportRequest
    from ._models_py3 import InstanceFailoverGroup
    from ._models_py3 import InstanceFailoverGroupReadOnlyEndpoint
    from ._models_py3 import InstanceFailoverGroupReadWriteEndpoint
    from ._models_py3 import InstancePool
    from ._models_py3 import InstancePoolEditionCapability
    from ._models_py3 import InstancePoolFamilyCapability
    from ._models_py3 import InstancePoolUpdate
    from ._models_py3 import InstancePoolVcoresCapability
    from ._models_py3 import Job
    from ._models_py3 import JobAgent
    from ._models_py3 import JobAgentUpdate
    from ._models_py3 import JobCredential
    from ._models_py3 import JobExecution
    from ._models_py3 import JobExecutionTarget
    from ._models_py3 import JobSchedule
    from ._models_py3 import JobStep
    from ._models_py3 import JobStepAction
    from ._models_py3 import JobStepExecutionOptions
    from ._models_py3 import JobStepOutput
    from ._models_py3 import JobTarget
    from ._models_py3 import JobTargetGroup
    from ._models_py3 import JobVersion
    from ._models_py3 import LicenseTypeCapability
    from ._models_py3 import LocationCapabilities
    from ._models_py3 import LogSizeCapability
    from ._models_py3 import LongTermRetentionBackup
    from ._models_py3 import ManagedBackupShortTermRetentionPolicy
    from ._models_py3 import ManagedDatabase
    from ._models_py3 import ManagedDatabaseRestoreDetailsResult
    from ._models_py3 import ManagedDatabaseSecurityAlertPolicy
    from ._models_py3 import ManagedDatabaseUpdate
    from ._models_py3 import ManagedInstance
    from ._models_py3 import ManagedInstanceAdministrator
    from ._models_py3 import ManagedInstanceEditionCapability
    from ._models_py3 import ManagedInstanceEncryptionProtector
    from ._models_py3 import ManagedInstanceFamilyCapability
    from ._models_py3 import ManagedInstanceKey
    from ._models_py3 import ManagedInstanceLongTermRetentionBackup
    from ._models_py3 import ManagedInstanceLongTermRetentionPolicy
    from ._models_py3 import ManagedInstanceOperation
    from ._models_py3 import ManagedInstancePairInfo
    from ._models_py3 import ManagedInstanceUpdate
    from ._models_py3 import ManagedInstanceVcoresCapability
    from ._models_py3 import ManagedInstanceVersionCapability
    from ._models_py3 import ManagedInstanceVulnerabilityAssessment
    from ._models_py3 import ManagedServerSecurityAlertPolicy
    from ._models_py3 import MaxSizeCapability
    from ._models_py3 import MaxSizeRangeCapability
    from ._models_py3 import Metric
    from ._models_py3 import MetricAvailability
    from ._models_py3 import MetricDefinition
    from ._models_py3 import MetricName
    from ._models_py3 import MetricValue
    from ._models_py3 import MinCapacityCapability
    from ._models_py3 import Name
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationImpact
    from ._models_py3 import PartnerInfo
    from ._models_py3 import PartnerRegionInfo
    from ._models_py3 import PerformanceLevelCapability
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateEndpointConnectionProperties
    from ._models_py3 import PrivateEndpointProperty
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkResourceProperties
    from ._models_py3 import PrivateLinkServiceConnectionStateProperty
    from ._models_py3 import ProxyResource
    from ._models_py3 import ReadScaleCapability
    from ._models_py3 import RecommendedElasticPool
    from ._models_py3 import RecommendedElasticPoolMetric
    from ._models_py3 import RecommendedIndex
    from ._models_py3 import RecoverableDatabase
    from ._models_py3 import RecoverableManagedDatabase
    from ._models_py3 import ReplicationLink
    from ._models_py3 import Resource
    from ._models_py3 import ResourceIdentity
    from ._models_py3 import ResourceMoveDefinition
    from ._models_py3 import RestorableDroppedDatabase
    from ._models_py3 import RestorableDroppedManagedDatabase
    from ._models_py3 import RestorePoint
    from ._models_py3 import SensitivityLabel
    from ._models_py3 import Server
    from ._models_py3 import ServerAutomaticTuning
    from ._models_py3 import ServerAzureADAdministrator
    from ._models_py3 import ServerBlobAuditingPolicy
    from ._models_py3 import ServerCommunicationLink
    from ._models_py3 import ServerConnectionPolicy
    from ._models_py3 import ServerDnsAlias
    from ._models_py3 import ServerDnsAliasAcquisition
    from ._models_py3 import ServerKey
    from ._models_py3 import ServerPrivateEndpointConnection
    from ._models_py3 import ServerSecurityAlertPolicy
    from ._models_py3 import ServerUpdate
    from ._models_py3 import ServerUsage
    from ._models_py3 import ServerVersionCapability
    from ._models_py3 import ServerVulnerabilityAssessment
    from ._models_py3 import ServiceObjective
    from ._models_py3 import ServiceObjectiveCapability
    from ._models_py3 import ServiceTierAdvisor
    from ._models_py3 import Sku
    from ._models_py3 import SloUsageMetric
    from ._models_py3 import StorageCapability
    from ._models_py3 import SubscriptionUsage
    from ._models_py3 import SyncAgent
    from ._models_py3 import SyncAgentKeyProperties
    from ._models_py3 import SyncAgentLinkedDatabase
    from ._models_py3 import SyncDatabaseIdProperties
    from ._models_py3 import SyncFullSchemaProperties
    from ._models_py3 import SyncFullSchemaTable
    from ._models_py3 import SyncFullSchemaTableColumn
    from ._models_py3 import SyncGroup
    from ._models_py3 import SyncGroupLogProperties
    from ._models_py3 import SyncGroupSchema
    from ._models_py3 import SyncGroupSchemaTable
    from ._models_py3 import SyncGroupSchemaTableColumn
    from ._models_py3 import SyncMember
    from ._models_py3 import TdeCertificate
    from ._models_py3 import TrackedResource
    from ._models_py3 import TransparentDataEncryption
    from ._models_py3 import TransparentDataEncryptionActivity
    from ._models_py3 import UnlinkParameters
    from ._models_py3 import Usage
    from ._models_py3 import VirtualCluster
    from ._models_py3 import VirtualClusterUpdate
    from ._models_py3 import VirtualNetworkRule
    from ._models_py3 import VulnerabilityAssessmentRecurringScansProperties
    from ._models_py3 import VulnerabilityAssessmentScanError
    from ._models_py3 import VulnerabilityAssessmentScanRecord
    from ._models_py3 import WorkloadClassifier
    from ._models_py3 import WorkloadGroup
except (SyntaxError, ImportError):
    from ._models import AutomaticTuningOptions
    from ._models import AutomaticTuningServerOptions
    from ._models import AutoPauseDelayTimeRange
    from ._models import BackupLongTermRetentionPolicy
    from ._models import BackupShortTermRetentionPolicy
    from ._models import CheckNameAvailabilityRequest
    from ._models import CheckNameAvailabilityResponse
    from ._models import CompleteDatabaseRestoreDefinition
    from ._models import CreateDatabaseRestorePointDefinition
    from ._models import Database
    from ._models import DatabaseAutomaticTuning
    from ._models import DatabaseBlobAuditingPolicy
    from ._models import DatabaseOperation
    from ._models import DatabaseSecurityAlertPolicy
    from ._models import DatabaseUpdate
    from ._models import DatabaseUsage
    from ._models import DatabaseVulnerabilityAssessment
    from ._models import DatabaseVulnerabilityAssessmentRuleBaseline
    from ._models import DatabaseVulnerabilityAssessmentRuleBaselineItem
    from ._models import DatabaseVulnerabilityAssessmentScansExport
    from ._models import DataMaskingPolicy
    from ._models import DataMaskingRule
    from ._models import EditionCapability
    from ._models import ElasticPool
    from ._models import ElasticPoolActivity
    from ._models import ElasticPoolDatabaseActivity
    from ._models import ElasticPoolEditionCapability
    from ._models import ElasticPoolOperation
    from ._models import ElasticPoolPerDatabaseMaxPerformanceLevelCapability
    from ._models import ElasticPoolPerDatabaseMinPerformanceLevelCapability
    from ._models import ElasticPoolPerDatabaseSettings
    from ._models import ElasticPoolPerformanceLevelCapability
    from ._models import ElasticPoolUpdate
    from ._models import EncryptionProtector
    from ._models import ExportRequest
    from ._models import ExtendedDatabaseBlobAuditingPolicy
    from ._models import ExtendedServerBlobAuditingPolicy
    from ._models import FailoverGroup
    from ._models import FailoverGroupReadOnlyEndpoint
    from ._models import FailoverGroupReadWriteEndpoint
    from ._models import FailoverGroupUpdate
    from ._models import FirewallRule
    from ._models import GeoBackupPolicy
    from ._models import ImportExportResponse
    from ._models import ImportExtensionRequest
    from ._models import ImportRequest
    from ._models import InstanceFailoverGroup
    from ._models import InstanceFailoverGroupReadOnlyEndpoint
    from ._models import InstanceFailoverGroupReadWriteEndpoint
    from ._models import InstancePool
    from ._models import InstancePoolEditionCapability
    from ._models import InstancePoolFamilyCapability
    from ._models import InstancePoolUpdate
    from ._models import InstancePoolVcoresCapability
    from ._models import Job
    from ._models import JobAgent
    from ._models import JobAgentUpdate
    from ._models import JobCredential
    from ._models import JobExecution
    from ._models import JobExecutionTarget
    from ._models import JobSchedule
    from ._models import JobStep
    from ._models import JobStepAction
    from ._models import JobStepExecutionOptions
    from ._models import JobStepOutput
    from ._models import JobTarget
    from ._models import JobTargetGroup
    from ._models import JobVersion
    from ._models import LicenseTypeCapability
    from ._models import LocationCapabilities
    from ._models import LogSizeCapability
    from ._models import LongTermRetentionBackup
    from ._models import ManagedBackupShortTermRetentionPolicy
    from ._models import ManagedDatabase
    from ._models import ManagedDatabaseRestoreDetailsResult
    from ._models import ManagedDatabaseSecurityAlertPolicy
    from ._models import ManagedDatabaseUpdate
    from ._models import ManagedInstance
    from ._models import ManagedInstanceAdministrator
    from ._models import ManagedInstanceEditionCapability
    from ._models import ManagedInstanceEncryptionProtector
    from ._models import ManagedInstanceFamilyCapability
    from ._models import ManagedInstanceKey
    from ._models import ManagedInstanceLongTermRetentionBackup
    from ._models import ManagedInstanceLongTermRetentionPolicy
    from ._models import ManagedInstanceOperation
    from ._models import ManagedInstancePairInfo
    from ._models import ManagedInstanceUpdate
    from ._models import ManagedInstanceVcoresCapability
    from ._models import ManagedInstanceVersionCapability
    from ._models import ManagedInstanceVulnerabilityAssessment
    from ._models import ManagedServerSecurityAlertPolicy
    from ._models import MaxSizeCapability
    from ._models import MaxSizeRangeCapability
    from ._models import Metric
    from ._models import MetricAvailability
    from ._models import MetricDefinition
    from ._models import MetricName
    from ._models import MetricValue
    from ._models import MinCapacityCapability
    from ._models import Name
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import OperationImpact
    from ._models import PartnerInfo
    from ._models import PartnerRegionInfo
    from ._models import PerformanceLevelCapability
    from ._models import PrivateEndpointConnection
    from ._models import PrivateEndpointConnectionProperties
    from ._models import PrivateEndpointProperty
    from ._models import PrivateLinkResource
    from ._models import PrivateLinkResourceProperties
    from ._models import PrivateLinkServiceConnectionStateProperty
    from ._models import ProxyResource
    from ._models import ReadScaleCapability
    from ._models import RecommendedElasticPool
    from ._models import RecommendedElasticPoolMetric
    from ._models import RecommendedIndex
    from ._models import RecoverableDatabase
    from ._models import RecoverableManagedDatabase
    from ._models import ReplicationLink
    from ._models import Resource
    from ._models import ResourceIdentity
    from ._models import ResourceMoveDefinition
    from ._models import RestorableDroppedDatabase
    from ._models import RestorableDroppedManagedDatabase
    from ._models import RestorePoint
    from ._models import SensitivityLabel
    from ._models import Server
    from ._models import ServerAutomaticTuning
    from ._models import ServerAzureADAdministrator
    from ._models import ServerBlobAuditingPolicy
    from ._models import ServerCommunicationLink
    from ._models import ServerConnectionPolicy
    from ._models import ServerDnsAlias
    from ._models import ServerDnsAliasAcquisition
    from ._models import ServerKey
    from ._models import ServerPrivateEndpointConnection
    from ._models import ServerSecurityAlertPolicy
    from ._models import ServerUpdate
    from ._models import ServerUsage
    from ._models import ServerVersionCapability
    from ._models import ServerVulnerabilityAssessment
    from ._models import ServiceObjective
    from ._models import ServiceObjectiveCapability
    from ._models import ServiceTierAdvisor
    from ._models import Sku
    from ._models import SloUsageMetric
    from ._models import StorageCapability
    from ._models import SubscriptionUsage
    from ._models import SyncAgent
    from ._models import SyncAgentKeyProperties
    from ._models import SyncAgentLinkedDatabase
    from ._models import SyncDatabaseIdProperties
    from ._models import SyncFullSchemaProperties
    from ._models import SyncFullSchemaTable
    from ._models import SyncFullSchemaTableColumn
    from ._models import SyncGroup
    from ._models import SyncGroupLogProperties
    from ._models import SyncGroupSchema
    from ._models import SyncGroupSchemaTable
    from ._models import SyncGroupSchemaTableColumn
    from ._models import SyncMember
    from ._models import TdeCertificate
    from ._models import TrackedResource
    from ._models import TransparentDataEncryption
    from ._models import TransparentDataEncryptionActivity
    from ._models import UnlinkParameters
    from ._models import Usage
    from ._models import VirtualCluster
    from ._models import VirtualClusterUpdate
    from ._models import VirtualNetworkRule
    from ._models import VulnerabilityAssessmentRecurringScansProperties
    from ._models import VulnerabilityAssessmentScanError
    from ._models import VulnerabilityAssessmentScanRecord
    from ._models import WorkloadClassifier
    from ._models import WorkloadGroup
from ._paged_models import BackupShortTermRetentionPolicyPaged
from ._paged_models import DatabaseBlobAuditingPolicyPaged
from ._paged_models import DatabaseOperationPaged
from ._paged_models import DatabasePaged
from ._paged_models import DatabaseUsagePaged
from ._paged_models import DatabaseVulnerabilityAssessmentPaged
from ._paged_models import DataMaskingRulePaged
from ._paged_models import ElasticPoolActivityPaged
from ._paged_models import ElasticPoolDatabaseActivityPaged
from ._paged_models import ElasticPoolOperationPaged
from ._paged_models import ElasticPoolPaged
from ._paged_models import EncryptionProtectorPaged
from ._paged_models import ExtendedDatabaseBlobAuditingPolicyPaged
from ._paged_models import ExtendedServerBlobAuditingPolicyPaged
from ._paged_models import FailoverGroupPaged
from ._paged_models import FirewallRulePaged
from ._paged_models import GeoBackupPolicyPaged
from ._paged_models import InstanceFailoverGroupPaged
from ._paged_models import InstancePoolPaged
from ._paged_models import JobAgentPaged
from ._paged_models import JobCredentialPaged
from ._paged_models import JobExecutionPaged
from ._paged_models import JobPaged
from ._paged_models import JobStepPaged
from ._paged_models import JobTargetGroupPaged
from ._paged_models import JobVersionPaged
from ._paged_models import LongTermRetentionBackupPaged
from ._paged_models import ManagedBackupShortTermRetentionPolicyPaged
from ._paged_models import ManagedDatabasePaged
from ._paged_models import ManagedDatabaseSecurityAlertPolicyPaged
from ._paged_models import ManagedInstanceAdministratorPaged
from ._paged_models import ManagedInstanceEncryptionProtectorPaged
from ._paged_models import ManagedInstanceKeyPaged
from ._paged_models import ManagedInstanceLongTermRetentionBackupPaged
from ._paged_models import ManagedInstanceLongTermRetentionPolicyPaged
from ._paged_models import ManagedInstanceOperationPaged
from ._paged_models import ManagedInstancePaged
from ._paged_models import ManagedInstanceVulnerabilityAssessmentPaged
from ._paged_models import ManagedServerSecurityAlertPolicyPaged
from ._paged_models import MetricDefinitionPaged
from ._paged_models import MetricPaged
from ._paged_models import OperationPaged
from ._paged_models import PrivateEndpointConnectionPaged
from ._paged_models import PrivateLinkResourcePaged
from ._paged_models import RecommendedElasticPoolMetricPaged
from ._paged_models import RecommendedElasticPoolPaged
from ._paged_models import RecoverableDatabasePaged
from ._paged_models import RecoverableManagedDatabasePaged
from ._paged_models import ReplicationLinkPaged
from ._paged_models import RestorableDroppedDatabasePaged
from ._paged_models import RestorableDroppedManagedDatabasePaged
from ._paged_models import RestorePointPaged
from ._paged_models import SensitivityLabelPaged
from ._paged_models import ServerAzureADAdministratorPaged
from ._paged_models import ServerBlobAuditingPolicyPaged
from ._paged_models import ServerCommunicationLinkPaged
from ._paged_models import ServerDnsAliasPaged
from ._paged_models import ServerKeyPaged
from ._paged_models import ServerPaged
from ._paged_models import ServerSecurityAlertPolicyPaged
from ._paged_models import ServerUsagePaged
from ._paged_models import ServerVulnerabilityAssessmentPaged
from ._paged_models import ServiceObjectivePaged
from ._paged_models import ServiceTierAdvisorPaged
from ._paged_models import SubscriptionUsagePaged
from ._paged_models import SyncAgentLinkedDatabasePaged
from ._paged_models import SyncAgentPaged
from ._paged_models import SyncDatabaseIdPropertiesPaged
from ._paged_models import SyncFullSchemaPropertiesPaged
from ._paged_models import SyncGroupLogPropertiesPaged
from ._paged_models import SyncGroupPaged
from ._paged_models import SyncMemberPaged
from ._paged_models import TransparentDataEncryptionActivityPaged
from ._paged_models import UsagePaged
from ._paged_models import VirtualClusterPaged
from ._paged_models import VirtualNetworkRulePaged
from ._paged_models import VulnerabilityAssessmentScanRecordPaged
from ._paged_models import WorkloadClassifierPaged
from ._paged_models import WorkloadGroupPaged
from ._sql_management_client_enums import (
    ServerConnectionType,
    SecurityAlertPolicyState,
    SecurityAlertPolicyEmailAccountAdmins,
    SecurityAlertPolicyUseServerDefault,
    DataMaskingState,
    DataMaskingRuleState,
    DataMaskingFunction,
    GeoBackupPolicyState,
    DatabaseEdition,
    ServiceObjectiveName,
    StorageKeyType,
    AuthenticationType,
    UnitType,
    PrimaryAggregationType,
    UnitDefinitionType,
    ElasticPoolEdition,
    ReplicationRole,
    ReplicationState,
    RecommendedIndexAction,
    RecommendedIndexState,
    RecommendedIndexType,
    TransparentDataEncryptionStatus,
    TransparentDataEncryptionActivityStatus,
    AutomaticTuningMode,
    AutomaticTuningOptionModeDesired,
    AutomaticTuningOptionModeActual,
    AutomaticTuningDisabledReason,
    ServerKeyType,
    ReadWriteEndpointFailoverPolicy,
    ReadOnlyEndpointFailoverPolicy,
    FailoverGroupReplicationRole,
    OperationOrigin,
    SyncAgentState,
    SyncMemberDbType,
    SyncGroupLogType,
    SyncConflictResolutionPolicy,
    SyncGroupState,
    SyncDirection,
    SyncMemberState,
    VirtualNetworkRuleState,
    BlobAuditingPolicyState,
    JobAgentState,
    JobExecutionLifecycle,
    ProvisioningState,
    JobTargetType,
    JobScheduleType,
    JobStepActionType,
    JobStepActionSource,
    JobStepOutputType,
    JobTargetGroupMembershipType,
    AutomaticTuningServerMode,
    AutomaticTuningServerReason,
    RestorePointType,
    SensitivityLabelRank,
    ManagementOperationState,
    CreateMode,
    SampleName,
    DatabaseStatus,
    CatalogCollationType,
    DatabaseLicenseType,
    DatabaseReadScale,
    ElasticPoolState,
    ElasticPoolLicenseType,
    VulnerabilityAssessmentScanTriggerType,
    VulnerabilityAssessmentScanState,
    InstanceFailoverGroupReplicationRole,
    InstancePoolLicenseType,
    IdentityType,
    ManagedServerCreateMode,
    ManagedInstanceLicenseType,
    ManagedInstanceProxyOverride,
    PrivateLinkServiceConnectionStateStatus,
    PrivateLinkServiceConnectionStateActionsRequire,
    PrivateEndpointProvisioningState,
    ServerPublicNetworkAccess,
    CheckNameAvailabilityReason,
    MaxSizeUnit,
    LogSizeUnit,
    CapabilityStatus,
    PerformanceLevelUnit,
    PauseDelayTimeUnit,
    ManagedDatabaseStatus,
    ManagedDatabaseCreateMode,
    LongTermRetentionDatabaseState,
    VulnerabilityAssessmentPolicyBaselineName,
    SensitivityLabelSource,
    ReplicaType,
    CapabilityGroup,
    DatabaseState1,
    DatabaseState2,
    DatabaseState3,
    DatabaseState4,
    DatabaseState5,
    DatabaseState6,
)

__all__ = [
    'AutomaticTuningOptions',
    'AutomaticTuningServerOptions',
    'AutoPauseDelayTimeRange',
    'BackupLongTermRetentionPolicy',
    'BackupShortTermRetentionPolicy',
    'CheckNameAvailabilityRequest',
    'CheckNameAvailabilityResponse',
    'CompleteDatabaseRestoreDefinition',
    'CreateDatabaseRestorePointDefinition',
    'Database',
    'DatabaseAutomaticTuning',
    'DatabaseBlobAuditingPolicy',
    'DatabaseOperation',
    'DatabaseSecurityAlertPolicy',
    'DatabaseUpdate',
    'DatabaseUsage',
    'DatabaseVulnerabilityAssessment',
    'DatabaseVulnerabilityAssessmentRuleBaseline',
    'DatabaseVulnerabilityAssessmentRuleBaselineItem',
    'DatabaseVulnerabilityAssessmentScansExport',
    'DataMaskingPolicy',
    'DataMaskingRule',
    'EditionCapability',
    'ElasticPool',
    'ElasticPoolActivity',
    'ElasticPoolDatabaseActivity',
    'ElasticPoolEditionCapability',
    'ElasticPoolOperation',
    'ElasticPoolPerDatabaseMaxPerformanceLevelCapability',
    'ElasticPoolPerDatabaseMinPerformanceLevelCapability',
    'ElasticPoolPerDatabaseSettings',
    'ElasticPoolPerformanceLevelCapability',
    'ElasticPoolUpdate',
    'EncryptionProtector',
    'ExportRequest',
    'ExtendedDatabaseBlobAuditingPolicy',
    'ExtendedServerBlobAuditingPolicy',
    'FailoverGroup',
    'FailoverGroupReadOnlyEndpoint',
    'FailoverGroupReadWriteEndpoint',
    'FailoverGroupUpdate',
    'FirewallRule',
    'GeoBackupPolicy',
    'ImportExportResponse',
    'ImportExtensionRequest',
    'ImportRequest',
    'InstanceFailoverGroup',
    'InstanceFailoverGroupReadOnlyEndpoint',
    'InstanceFailoverGroupReadWriteEndpoint',
    'InstancePool',
    'InstancePoolEditionCapability',
    'InstancePoolFamilyCapability',
    'InstancePoolUpdate',
    'InstancePoolVcoresCapability',
    'Job',
    'JobAgent',
    'JobAgentUpdate',
    'JobCredential',
    'JobExecution',
    'JobExecutionTarget',
    'JobSchedule',
    'JobStep',
    'JobStepAction',
    'JobStepExecutionOptions',
    'JobStepOutput',
    'JobTarget',
    'JobTargetGroup',
    'JobVersion',
    'LicenseTypeCapability',
    'LocationCapabilities',
    'LogSizeCapability',
    'LongTermRetentionBackup',
    'ManagedBackupShortTermRetentionPolicy',
    'ManagedDatabase',
    'ManagedDatabaseRestoreDetailsResult',
    'ManagedDatabaseSecurityAlertPolicy',
    'ManagedDatabaseUpdate',
    'ManagedInstance',
    'ManagedInstanceAdministrator',
    'ManagedInstanceEditionCapability',
    'ManagedInstanceEncryptionProtector',
    'ManagedInstanceFamilyCapability',
    'ManagedInstanceKey',
    'ManagedInstanceLongTermRetentionBackup',
    'ManagedInstanceLongTermRetentionPolicy',
    'ManagedInstanceOperation',
    'ManagedInstancePairInfo',
    'ManagedInstanceUpdate',
    'ManagedInstanceVcoresCapability',
    'ManagedInstanceVersionCapability',
    'ManagedInstanceVulnerabilityAssessment',
    'ManagedServerSecurityAlertPolicy',
    'MaxSizeCapability',
    'MaxSizeRangeCapability',
    'Metric',
    'MetricAvailability',
    'MetricDefinition',
    'MetricName',
    'MetricValue',
    'MinCapacityCapability',
    'Name',
    'Operation',
    'OperationDisplay',
    'OperationImpact',
    'PartnerInfo',
    'PartnerRegionInfo',
    'PerformanceLevelCapability',
    'PrivateEndpointConnection',
    'PrivateEndpointConnectionProperties',
    'PrivateEndpointProperty',
    'PrivateLinkResource',
    'PrivateLinkResourceProperties',
    'PrivateLinkServiceConnectionStateProperty',
    'ProxyResource',
    'ReadScaleCapability',
    'RecommendedElasticPool',
    'RecommendedElasticPoolMetric',
    'RecommendedIndex',
    'RecoverableDatabase',
    'RecoverableManagedDatabase',
    'ReplicationLink',
    'Resource',
    'ResourceIdentity',
    'ResourceMoveDefinition',
    'RestorableDroppedDatabase',
    'RestorableDroppedManagedDatabase',
    'RestorePoint',
    'SensitivityLabel',
    'Server',
    'ServerAutomaticTuning',
    'ServerAzureADAdministrator',
    'ServerBlobAuditingPolicy',
    'ServerCommunicationLink',
    'ServerConnectionPolicy',
    'ServerDnsAlias',
    'ServerDnsAliasAcquisition',
    'ServerKey',
    'ServerPrivateEndpointConnection',
    'ServerSecurityAlertPolicy',
    'ServerUpdate',
    'ServerUsage',
    'ServerVersionCapability',
    'ServerVulnerabilityAssessment',
    'ServiceObjective',
    'ServiceObjectiveCapability',
    'ServiceTierAdvisor',
    'Sku',
    'SloUsageMetric',
    'StorageCapability',
    'SubscriptionUsage',
    'SyncAgent',
    'SyncAgentKeyProperties',
    'SyncAgentLinkedDatabase',
    'SyncDatabaseIdProperties',
    'SyncFullSchemaProperties',
    'SyncFullSchemaTable',
    'SyncFullSchemaTableColumn',
    'SyncGroup',
    'SyncGroupLogProperties',
    'SyncGroupSchema',
    'SyncGroupSchemaTable',
    'SyncGroupSchemaTableColumn',
    'SyncMember',
    'TdeCertificate',
    'TrackedResource',
    'TransparentDataEncryption',
    'TransparentDataEncryptionActivity',
    'UnlinkParameters',
    'Usage',
    'VirtualCluster',
    'VirtualClusterUpdate',
    'VirtualNetworkRule',
    'VulnerabilityAssessmentRecurringScansProperties',
    'VulnerabilityAssessmentScanError',
    'VulnerabilityAssessmentScanRecord',
    'WorkloadClassifier',
    'WorkloadGroup',
    'RecoverableDatabasePaged',
    'RestorableDroppedDatabasePaged',
    'DataMaskingRulePaged',
    'FirewallRulePaged',
    'GeoBackupPolicyPaged',
    'MetricPaged',
    'MetricDefinitionPaged',
    'DatabasePaged',
    'ElasticPoolPaged',
    'RecommendedElasticPoolPaged',
    'RecommendedElasticPoolMetricPaged',
    'ReplicationLinkPaged',
    'ServerCommunicationLinkPaged',
    'ServiceObjectivePaged',
    'ElasticPoolActivityPaged',
    'ElasticPoolDatabaseActivityPaged',
    'ServiceTierAdvisorPaged',
    'TransparentDataEncryptionActivityPaged',
    'ServerUsagePaged',
    'DatabaseUsagePaged',
    'EncryptionProtectorPaged',
    'FailoverGroupPaged',
    'OperationPaged',
    'ServerKeyPaged',
    'SyncAgentPaged',
    'SyncAgentLinkedDatabasePaged',
    'SyncDatabaseIdPropertiesPaged',
    'SyncFullSchemaPropertiesPaged',
    'SyncGroupLogPropertiesPaged',
    'SyncGroupPaged',
    'SyncMemberPaged',
    'SubscriptionUsagePaged',
    'VirtualClusterPaged',
    'VirtualNetworkRulePaged',
    'ExtendedDatabaseBlobAuditingPolicyPaged',
    'ExtendedServerBlobAuditingPolicyPaged',
    'ServerBlobAuditingPolicyPaged',
    'DatabaseBlobAuditingPolicyPaged',
    'DatabaseVulnerabilityAssessmentPaged',
    'JobAgentPaged',
    'JobCredentialPaged',
    'JobExecutionPaged',
    'JobPaged',
    'JobStepPaged',
    'JobTargetGroupPaged',
    'JobVersionPaged',
    'LongTermRetentionBackupPaged',
    'ManagedBackupShortTermRetentionPolicyPaged',
    'ServerDnsAliasPaged',
    'ServerSecurityAlertPolicyPaged',
    'RestorableDroppedManagedDatabasePaged',
    'RestorePointPaged',
    'ManagedDatabaseSecurityAlertPolicyPaged',
    'ManagedServerSecurityAlertPolicyPaged',
    'SensitivityLabelPaged',
    'ManagedInstanceAdministratorPaged',
    'DatabaseOperationPaged',
    'ElasticPoolOperationPaged',
    'VulnerabilityAssessmentScanRecordPaged',
    'InstanceFailoverGroupPaged',
    'BackupShortTermRetentionPolicyPaged',
    'ManagedInstanceKeyPaged',
    'ManagedInstanceEncryptionProtectorPaged',
    'RecoverableManagedDatabasePaged',
    'ManagedInstanceVulnerabilityAssessmentPaged',
    'ServerVulnerabilityAssessmentPaged',
    'InstancePoolPaged',
    'UsagePaged',
    'ManagedInstancePaged',
    'PrivateEndpointConnectionPaged',
    'PrivateLinkResourcePaged',
    'ServerPaged',
    'ManagedInstanceLongTermRetentionBackupPaged',
    'ManagedInstanceLongTermRetentionPolicyPaged',
    'WorkloadGroupPaged',
    'WorkloadClassifierPaged',
    'ManagedDatabasePaged',
    'ServerAzureADAdministratorPaged',
    'ManagedInstanceOperationPaged',
    'ServerConnectionType',
    'SecurityAlertPolicyState',
    'SecurityAlertPolicyEmailAccountAdmins',
    'SecurityAlertPolicyUseServerDefault',
    'DataMaskingState',
    'DataMaskingRuleState',
    'DataMaskingFunction',
    'GeoBackupPolicyState',
    'DatabaseEdition',
    'ServiceObjectiveName',
    'StorageKeyType',
    'AuthenticationType',
    'UnitType',
    'PrimaryAggregationType',
    'UnitDefinitionType',
    'ElasticPoolEdition',
    'ReplicationRole',
    'ReplicationState',
    'RecommendedIndexAction',
    'RecommendedIndexState',
    'RecommendedIndexType',
    'TransparentDataEncryptionStatus',
    'TransparentDataEncryptionActivityStatus',
    'AutomaticTuningMode',
    'AutomaticTuningOptionModeDesired',
    'AutomaticTuningOptionModeActual',
    'AutomaticTuningDisabledReason',
    'ServerKeyType',
    'ReadWriteEndpointFailoverPolicy',
    'ReadOnlyEndpointFailoverPolicy',
    'FailoverGroupReplicationRole',
    'OperationOrigin',
    'SyncAgentState',
    'SyncMemberDbType',
    'SyncGroupLogType',
    'SyncConflictResolutionPolicy',
    'SyncGroupState',
    'SyncDirection',
    'SyncMemberState',
    'VirtualNetworkRuleState',
    'BlobAuditingPolicyState',
    'JobAgentState',
    'JobExecutionLifecycle',
    'ProvisioningState',
    'JobTargetType',
    'JobScheduleType',
    'JobStepActionType',
    'JobStepActionSource',
    'JobStepOutputType',
    'JobTargetGroupMembershipType',
    'AutomaticTuningServerMode',
    'AutomaticTuningServerReason',
    'RestorePointType',
    'SensitivityLabelRank',
    'ManagementOperationState',
    'CreateMode',
    'SampleName',
    'DatabaseStatus',
    'CatalogCollationType',
    'DatabaseLicenseType',
    'DatabaseReadScale',
    'ElasticPoolState',
    'ElasticPoolLicenseType',
    'VulnerabilityAssessmentScanTriggerType',
    'VulnerabilityAssessmentScanState',
    'InstanceFailoverGroupReplicationRole',
    'InstancePoolLicenseType',
    'IdentityType',
    'ManagedServerCreateMode',
    'ManagedInstanceLicenseType',
    'ManagedInstanceProxyOverride',
    'PrivateLinkServiceConnectionStateStatus',
    'PrivateLinkServiceConnectionStateActionsRequire',
    'PrivateEndpointProvisioningState',
    'ServerPublicNetworkAccess',
    'CheckNameAvailabilityReason',
    'MaxSizeUnit',
    'LogSizeUnit',
    'CapabilityStatus',
    'PerformanceLevelUnit',
    'PauseDelayTimeUnit',
    'ManagedDatabaseStatus',
    'ManagedDatabaseCreateMode',
    'LongTermRetentionDatabaseState',
    'VulnerabilityAssessmentPolicyBaselineName',
    'SensitivityLabelSource',
    'ReplicaType',
    'CapabilityGroup',
    'DatabaseState1',
    'DatabaseState2',
    'DatabaseState3',
    'DatabaseState4',
    'DatabaseState5',
    'DatabaseState6',
]
