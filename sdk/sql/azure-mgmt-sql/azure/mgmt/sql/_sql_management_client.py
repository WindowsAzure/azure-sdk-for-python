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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer

from ._configuration import SqlManagementClientConfiguration
from .operations import RecoverableDatabasesOperations
from .operations import RestorableDroppedDatabasesOperations
from .operations import ServerConnectionPoliciesOperations
from .operations import DatabaseThreatDetectionPoliciesOperations
from .operations import DataMaskingPoliciesOperations
from .operations import DataMaskingRulesOperations
from .operations import FirewallRulesOperations
from .operations import GeoBackupPoliciesOperations
from .operations import DatabasesOperations
from .operations import ElasticPoolsOperations
from .operations import RecommendedElasticPoolsOperations
from .operations import ReplicationLinksOperations
from .operations import ServerCommunicationLinksOperations
from .operations import ServiceObjectivesOperations
from .operations import ElasticPoolActivitiesOperations
from .operations import ElasticPoolDatabaseActivitiesOperations
from .operations import ServiceTierAdvisorsOperations
from .operations import TransparentDataEncryptionsOperations
from .operations import TransparentDataEncryptionActivitiesOperations
from .operations import ServerUsagesOperations
from .operations import DatabaseUsagesOperations
from .operations import DatabaseAutomaticTuningOperations
from .operations import EncryptionProtectorsOperations
from .operations import FailoverGroupsOperations
from .operations import Operations
from .operations import ServerKeysOperations
from .operations import SyncAgentsOperations
from .operations import SyncGroupsOperations
from .operations import SyncMembersOperations
from .operations import SubscriptionUsagesOperations
from .operations import VirtualClustersOperations
from .operations import VirtualNetworkRulesOperations
from .operations import ExtendedDatabaseBlobAuditingPoliciesOperations
from .operations import ExtendedServerBlobAuditingPoliciesOperations
from .operations import ServerBlobAuditingPoliciesOperations
from .operations import DatabaseBlobAuditingPoliciesOperations
from .operations import DatabaseVulnerabilityAssessmentRuleBaselinesOperations
from .operations import DatabaseVulnerabilityAssessmentsOperations
from .operations import JobAgentsOperations
from .operations import JobCredentialsOperations
from .operations import JobExecutionsOperations
from .operations import JobsOperations
from .operations import JobStepExecutionsOperations
from .operations import JobStepsOperations
from .operations import JobTargetExecutionsOperations
from .operations import JobTargetGroupsOperations
from .operations import JobVersionsOperations
from .operations import LongTermRetentionBackupsOperations
from .operations import BackupLongTermRetentionPoliciesOperations
from .operations import ManagedBackupShortTermRetentionPoliciesOperations
from .operations import ManagedRestorableDroppedDatabaseBackupShortTermRetentionPoliciesOperations
from .operations import ServerAutomaticTuningOperations
from .operations import ServerDnsAliasesOperations
from .operations import ServerSecurityAlertPoliciesOperations
from .operations import RestorableDroppedManagedDatabasesOperations
from .operations import RestorePointsOperations
from .operations import ManagedDatabaseSecurityAlertPoliciesOperations
from .operations import ManagedServerSecurityAlertPoliciesOperations
from .operations import SensitivityLabelsOperations
from .operations import ManagedInstanceAdministratorsOperations
from .operations import DatabaseOperations
from .operations import ElasticPoolOperations
from .operations import DatabaseVulnerabilityAssessmentScansOperations
from .operations import ManagedDatabaseVulnerabilityAssessmentRuleBaselinesOperations
from .operations import ManagedDatabaseVulnerabilityAssessmentScansOperations
from .operations import ManagedDatabaseVulnerabilityAssessmentsOperations
from .operations import InstanceFailoverGroupsOperations
from .operations import BackupShortTermRetentionPoliciesOperations
from .operations import TdeCertificatesOperations
from .operations import ManagedInstanceTdeCertificatesOperations
from .operations import ManagedInstanceKeysOperations
from .operations import ManagedInstanceEncryptionProtectorsOperations
from .operations import RecoverableManagedDatabasesOperations
from .operations import ManagedInstanceVulnerabilityAssessmentsOperations
from .operations import ServerVulnerabilityAssessmentsOperations
from .operations import ManagedDatabaseSensitivityLabelsOperations
from .operations import InstancePoolsOperations
from .operations import UsagesOperations
from .operations import ManagedInstancesOperations
from .operations import PrivateEndpointConnectionsOperations
from .operations import PrivateLinkResourcesOperations
from .operations import ServersOperations
from .operations import CapabilitiesOperations
from .operations import LongTermRetentionManagedInstanceBackupsOperations
from .operations import ManagedInstanceLongTermRetentionPoliciesOperations
from .operations import WorkloadGroupsOperations
from .operations import WorkloadClassifiersOperations
from .operations import ManagedDatabaseRestoreDetailsOperations
from .operations import ManagedDatabasesOperations
from .operations import ServerAzureADAdministratorsOperations
from .operations import ManagedInstanceOperations
from . import models


class SqlManagementClient(SDKClient):
    """The Azure SQL Database management API provides a RESTful set of web services that interact with Azure SQL Database services to manage your databases. The API enables you to create, retrieve, update, and delete databases.

    :ivar config: Configuration for client.
    :vartype config: SqlManagementClientConfiguration

    :ivar recoverable_databases: RecoverableDatabases operations
    :vartype recoverable_databases: azure.mgmt.sql.operations.RecoverableDatabasesOperations
    :ivar restorable_dropped_databases: RestorableDroppedDatabases operations
    :vartype restorable_dropped_databases: azure.mgmt.sql.operations.RestorableDroppedDatabasesOperations
    :ivar server_connection_policies: ServerConnectionPolicies operations
    :vartype server_connection_policies: azure.mgmt.sql.operations.ServerConnectionPoliciesOperations
    :ivar database_threat_detection_policies: DatabaseThreatDetectionPolicies operations
    :vartype database_threat_detection_policies: azure.mgmt.sql.operations.DatabaseThreatDetectionPoliciesOperations
    :ivar data_masking_policies: DataMaskingPolicies operations
    :vartype data_masking_policies: azure.mgmt.sql.operations.DataMaskingPoliciesOperations
    :ivar data_masking_rules: DataMaskingRules operations
    :vartype data_masking_rules: azure.mgmt.sql.operations.DataMaskingRulesOperations
    :ivar firewall_rules: FirewallRules operations
    :vartype firewall_rules: azure.mgmt.sql.operations.FirewallRulesOperations
    :ivar geo_backup_policies: GeoBackupPolicies operations
    :vartype geo_backup_policies: azure.mgmt.sql.operations.GeoBackupPoliciesOperations
    :ivar databases: Databases operations
    :vartype databases: azure.mgmt.sql.operations.DatabasesOperations
    :ivar elastic_pools: ElasticPools operations
    :vartype elastic_pools: azure.mgmt.sql.operations.ElasticPoolsOperations
    :ivar recommended_elastic_pools: RecommendedElasticPools operations
    :vartype recommended_elastic_pools: azure.mgmt.sql.operations.RecommendedElasticPoolsOperations
    :ivar replication_links: ReplicationLinks operations
    :vartype replication_links: azure.mgmt.sql.operations.ReplicationLinksOperations
    :ivar server_communication_links: ServerCommunicationLinks operations
    :vartype server_communication_links: azure.mgmt.sql.operations.ServerCommunicationLinksOperations
    :ivar service_objectives: ServiceObjectives operations
    :vartype service_objectives: azure.mgmt.sql.operations.ServiceObjectivesOperations
    :ivar elastic_pool_activities: ElasticPoolActivities operations
    :vartype elastic_pool_activities: azure.mgmt.sql.operations.ElasticPoolActivitiesOperations
    :ivar elastic_pool_database_activities: ElasticPoolDatabaseActivities operations
    :vartype elastic_pool_database_activities: azure.mgmt.sql.operations.ElasticPoolDatabaseActivitiesOperations
    :ivar service_tier_advisors: ServiceTierAdvisors operations
    :vartype service_tier_advisors: azure.mgmt.sql.operations.ServiceTierAdvisorsOperations
    :ivar transparent_data_encryptions: TransparentDataEncryptions operations
    :vartype transparent_data_encryptions: azure.mgmt.sql.operations.TransparentDataEncryptionsOperations
    :ivar transparent_data_encryption_activities: TransparentDataEncryptionActivities operations
    :vartype transparent_data_encryption_activities: azure.mgmt.sql.operations.TransparentDataEncryptionActivitiesOperations
    :ivar server_usages: ServerUsages operations
    :vartype server_usages: azure.mgmt.sql.operations.ServerUsagesOperations
    :ivar database_usages: DatabaseUsages operations
    :vartype database_usages: azure.mgmt.sql.operations.DatabaseUsagesOperations
    :ivar database_automatic_tuning: DatabaseAutomaticTuning operations
    :vartype database_automatic_tuning: azure.mgmt.sql.operations.DatabaseAutomaticTuningOperations
    :ivar encryption_protectors: EncryptionProtectors operations
    :vartype encryption_protectors: azure.mgmt.sql.operations.EncryptionProtectorsOperations
    :ivar failover_groups: FailoverGroups operations
    :vartype failover_groups: azure.mgmt.sql.operations.FailoverGroupsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.sql.operations.Operations
    :ivar server_keys: ServerKeys operations
    :vartype server_keys: azure.mgmt.sql.operations.ServerKeysOperations
    :ivar sync_agents: SyncAgents operations
    :vartype sync_agents: azure.mgmt.sql.operations.SyncAgentsOperations
    :ivar sync_groups: SyncGroups operations
    :vartype sync_groups: azure.mgmt.sql.operations.SyncGroupsOperations
    :ivar sync_members: SyncMembers operations
    :vartype sync_members: azure.mgmt.sql.operations.SyncMembersOperations
    :ivar subscription_usages: SubscriptionUsages operations
    :vartype subscription_usages: azure.mgmt.sql.operations.SubscriptionUsagesOperations
    :ivar virtual_clusters: VirtualClusters operations
    :vartype virtual_clusters: azure.mgmt.sql.operations.VirtualClustersOperations
    :ivar virtual_network_rules: VirtualNetworkRules operations
    :vartype virtual_network_rules: azure.mgmt.sql.operations.VirtualNetworkRulesOperations
    :ivar extended_database_blob_auditing_policies: ExtendedDatabaseBlobAuditingPolicies operations
    :vartype extended_database_blob_auditing_policies: azure.mgmt.sql.operations.ExtendedDatabaseBlobAuditingPoliciesOperations
    :ivar extended_server_blob_auditing_policies: ExtendedServerBlobAuditingPolicies operations
    :vartype extended_server_blob_auditing_policies: azure.mgmt.sql.operations.ExtendedServerBlobAuditingPoliciesOperations
    :ivar server_blob_auditing_policies: ServerBlobAuditingPolicies operations
    :vartype server_blob_auditing_policies: azure.mgmt.sql.operations.ServerBlobAuditingPoliciesOperations
    :ivar database_blob_auditing_policies: DatabaseBlobAuditingPolicies operations
    :vartype database_blob_auditing_policies: azure.mgmt.sql.operations.DatabaseBlobAuditingPoliciesOperations
    :ivar database_vulnerability_assessment_rule_baselines: DatabaseVulnerabilityAssessmentRuleBaselines operations
    :vartype database_vulnerability_assessment_rule_baselines: azure.mgmt.sql.operations.DatabaseVulnerabilityAssessmentRuleBaselinesOperations
    :ivar database_vulnerability_assessments: DatabaseVulnerabilityAssessments operations
    :vartype database_vulnerability_assessments: azure.mgmt.sql.operations.DatabaseVulnerabilityAssessmentsOperations
    :ivar job_agents: JobAgents operations
    :vartype job_agents: azure.mgmt.sql.operations.JobAgentsOperations
    :ivar job_credentials: JobCredentials operations
    :vartype job_credentials: azure.mgmt.sql.operations.JobCredentialsOperations
    :ivar job_executions: JobExecutions operations
    :vartype job_executions: azure.mgmt.sql.operations.JobExecutionsOperations
    :ivar jobs: Jobs operations
    :vartype jobs: azure.mgmt.sql.operations.JobsOperations
    :ivar job_step_executions: JobStepExecutions operations
    :vartype job_step_executions: azure.mgmt.sql.operations.JobStepExecutionsOperations
    :ivar job_steps: JobSteps operations
    :vartype job_steps: azure.mgmt.sql.operations.JobStepsOperations
    :ivar job_target_executions: JobTargetExecutions operations
    :vartype job_target_executions: azure.mgmt.sql.operations.JobTargetExecutionsOperations
    :ivar job_target_groups: JobTargetGroups operations
    :vartype job_target_groups: azure.mgmt.sql.operations.JobTargetGroupsOperations
    :ivar job_versions: JobVersions operations
    :vartype job_versions: azure.mgmt.sql.operations.JobVersionsOperations
    :ivar long_term_retention_backups: LongTermRetentionBackups operations
    :vartype long_term_retention_backups: azure.mgmt.sql.operations.LongTermRetentionBackupsOperations
    :ivar backup_long_term_retention_policies: BackupLongTermRetentionPolicies operations
    :vartype backup_long_term_retention_policies: azure.mgmt.sql.operations.BackupLongTermRetentionPoliciesOperations
    :ivar managed_backup_short_term_retention_policies: ManagedBackupShortTermRetentionPolicies operations
    :vartype managed_backup_short_term_retention_policies: azure.mgmt.sql.operations.ManagedBackupShortTermRetentionPoliciesOperations
    :ivar managed_restorable_dropped_database_backup_short_term_retention_policies: ManagedRestorableDroppedDatabaseBackupShortTermRetentionPolicies operations
    :vartype managed_restorable_dropped_database_backup_short_term_retention_policies: azure.mgmt.sql.operations.ManagedRestorableDroppedDatabaseBackupShortTermRetentionPoliciesOperations
    :ivar server_automatic_tuning: ServerAutomaticTuning operations
    :vartype server_automatic_tuning: azure.mgmt.sql.operations.ServerAutomaticTuningOperations
    :ivar server_dns_aliases: ServerDnsAliases operations
    :vartype server_dns_aliases: azure.mgmt.sql.operations.ServerDnsAliasesOperations
    :ivar server_security_alert_policies: ServerSecurityAlertPolicies operations
    :vartype server_security_alert_policies: azure.mgmt.sql.operations.ServerSecurityAlertPoliciesOperations
    :ivar restorable_dropped_managed_databases: RestorableDroppedManagedDatabases operations
    :vartype restorable_dropped_managed_databases: azure.mgmt.sql.operations.RestorableDroppedManagedDatabasesOperations
    :ivar restore_points: RestorePoints operations
    :vartype restore_points: azure.mgmt.sql.operations.RestorePointsOperations
    :ivar managed_database_security_alert_policies: ManagedDatabaseSecurityAlertPolicies operations
    :vartype managed_database_security_alert_policies: azure.mgmt.sql.operations.ManagedDatabaseSecurityAlertPoliciesOperations
    :ivar managed_server_security_alert_policies: ManagedServerSecurityAlertPolicies operations
    :vartype managed_server_security_alert_policies: azure.mgmt.sql.operations.ManagedServerSecurityAlertPoliciesOperations
    :ivar sensitivity_labels: SensitivityLabels operations
    :vartype sensitivity_labels: azure.mgmt.sql.operations.SensitivityLabelsOperations
    :ivar managed_instance_administrators: ManagedInstanceAdministrators operations
    :vartype managed_instance_administrators: azure.mgmt.sql.operations.ManagedInstanceAdministratorsOperations
    :ivar database_operations: DatabaseOperations operations
    :vartype database_operations: azure.mgmt.sql.operations.DatabaseOperations
    :ivar elastic_pool_operations: ElasticPoolOperations operations
    :vartype elastic_pool_operations: azure.mgmt.sql.operations.ElasticPoolOperations
    :ivar database_vulnerability_assessment_scans: DatabaseVulnerabilityAssessmentScans operations
    :vartype database_vulnerability_assessment_scans: azure.mgmt.sql.operations.DatabaseVulnerabilityAssessmentScansOperations
    :ivar managed_database_vulnerability_assessment_rule_baselines: ManagedDatabaseVulnerabilityAssessmentRuleBaselines operations
    :vartype managed_database_vulnerability_assessment_rule_baselines: azure.mgmt.sql.operations.ManagedDatabaseVulnerabilityAssessmentRuleBaselinesOperations
    :ivar managed_database_vulnerability_assessment_scans: ManagedDatabaseVulnerabilityAssessmentScans operations
    :vartype managed_database_vulnerability_assessment_scans: azure.mgmt.sql.operations.ManagedDatabaseVulnerabilityAssessmentScansOperations
    :ivar managed_database_vulnerability_assessments: ManagedDatabaseVulnerabilityAssessments operations
    :vartype managed_database_vulnerability_assessments: azure.mgmt.sql.operations.ManagedDatabaseVulnerabilityAssessmentsOperations
    :ivar instance_failover_groups: InstanceFailoverGroups operations
    :vartype instance_failover_groups: azure.mgmt.sql.operations.InstanceFailoverGroupsOperations
    :ivar backup_short_term_retention_policies: BackupShortTermRetentionPolicies operations
    :vartype backup_short_term_retention_policies: azure.mgmt.sql.operations.BackupShortTermRetentionPoliciesOperations
    :ivar tde_certificates: TdeCertificates operations
    :vartype tde_certificates: azure.mgmt.sql.operations.TdeCertificatesOperations
    :ivar managed_instance_tde_certificates: ManagedInstanceTdeCertificates operations
    :vartype managed_instance_tde_certificates: azure.mgmt.sql.operations.ManagedInstanceTdeCertificatesOperations
    :ivar managed_instance_keys: ManagedInstanceKeys operations
    :vartype managed_instance_keys: azure.mgmt.sql.operations.ManagedInstanceKeysOperations
    :ivar managed_instance_encryption_protectors: ManagedInstanceEncryptionProtectors operations
    :vartype managed_instance_encryption_protectors: azure.mgmt.sql.operations.ManagedInstanceEncryptionProtectorsOperations
    :ivar recoverable_managed_databases: RecoverableManagedDatabases operations
    :vartype recoverable_managed_databases: azure.mgmt.sql.operations.RecoverableManagedDatabasesOperations
    :ivar managed_instance_vulnerability_assessments: ManagedInstanceVulnerabilityAssessments operations
    :vartype managed_instance_vulnerability_assessments: azure.mgmt.sql.operations.ManagedInstanceVulnerabilityAssessmentsOperations
    :ivar server_vulnerability_assessments: ServerVulnerabilityAssessments operations
    :vartype server_vulnerability_assessments: azure.mgmt.sql.operations.ServerVulnerabilityAssessmentsOperations
    :ivar managed_database_sensitivity_labels: ManagedDatabaseSensitivityLabels operations
    :vartype managed_database_sensitivity_labels: azure.mgmt.sql.operations.ManagedDatabaseSensitivityLabelsOperations
    :ivar instance_pools: InstancePools operations
    :vartype instance_pools: azure.mgmt.sql.operations.InstancePoolsOperations
    :ivar usages: Usages operations
    :vartype usages: azure.mgmt.sql.operations.UsagesOperations
    :ivar managed_instances: ManagedInstances operations
    :vartype managed_instances: azure.mgmt.sql.operations.ManagedInstancesOperations
    :ivar private_endpoint_connections: PrivateEndpointConnections operations
    :vartype private_endpoint_connections: azure.mgmt.sql.operations.PrivateEndpointConnectionsOperations
    :ivar private_link_resources: PrivateLinkResources operations
    :vartype private_link_resources: azure.mgmt.sql.operations.PrivateLinkResourcesOperations
    :ivar servers: Servers operations
    :vartype servers: azure.mgmt.sql.operations.ServersOperations
    :ivar capabilities: Capabilities operations
    :vartype capabilities: azure.mgmt.sql.operations.CapabilitiesOperations
    :ivar long_term_retention_managed_instance_backups: LongTermRetentionManagedInstanceBackups operations
    :vartype long_term_retention_managed_instance_backups: azure.mgmt.sql.operations.LongTermRetentionManagedInstanceBackupsOperations
    :ivar managed_instance_long_term_retention_policies: ManagedInstanceLongTermRetentionPolicies operations
    :vartype managed_instance_long_term_retention_policies: azure.mgmt.sql.operations.ManagedInstanceLongTermRetentionPoliciesOperations
    :ivar workload_groups: WorkloadGroups operations
    :vartype workload_groups: azure.mgmt.sql.operations.WorkloadGroupsOperations
    :ivar workload_classifiers: WorkloadClassifiers operations
    :vartype workload_classifiers: azure.mgmt.sql.operations.WorkloadClassifiersOperations
    :ivar managed_database_restore_details: ManagedDatabaseRestoreDetails operations
    :vartype managed_database_restore_details: azure.mgmt.sql.operations.ManagedDatabaseRestoreDetailsOperations
    :ivar managed_databases: ManagedDatabases operations
    :vartype managed_databases: azure.mgmt.sql.operations.ManagedDatabasesOperations
    :ivar server_azure_ad_administrators: ServerAzureADAdministrators operations
    :vartype server_azure_ad_administrators: azure.mgmt.sql.operations.ServerAzureADAdministratorsOperations
    :ivar managed_instance_operations: ManagedInstanceOperations operations
    :vartype managed_instance_operations: azure.mgmt.sql.operations.ManagedInstanceOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The subscription ID that identifies an Azure
     subscription.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = SqlManagementClientConfiguration(credentials, subscription_id, base_url)
        super(SqlManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.recoverable_databases = RecoverableDatabasesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.restorable_dropped_databases = RestorableDroppedDatabasesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_connection_policies = ServerConnectionPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_threat_detection_policies = DatabaseThreatDetectionPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.data_masking_policies = DataMaskingPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.data_masking_rules = DataMaskingRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.firewall_rules = FirewallRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.geo_backup_policies = GeoBackupPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.databases = DatabasesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.elastic_pools = ElasticPoolsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.recommended_elastic_pools = RecommendedElasticPoolsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.replication_links = ReplicationLinksOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_communication_links = ServerCommunicationLinksOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.service_objectives = ServiceObjectivesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.elastic_pool_activities = ElasticPoolActivitiesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.elastic_pool_database_activities = ElasticPoolDatabaseActivitiesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.service_tier_advisors = ServiceTierAdvisorsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.transparent_data_encryptions = TransparentDataEncryptionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.transparent_data_encryption_activities = TransparentDataEncryptionActivitiesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_usages = ServerUsagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_usages = DatabaseUsagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_automatic_tuning = DatabaseAutomaticTuningOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.encryption_protectors = EncryptionProtectorsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.failover_groups = FailoverGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_keys = ServerKeysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.sync_agents = SyncAgentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.sync_groups = SyncGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.sync_members = SyncMembersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subscription_usages = SubscriptionUsagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_clusters = VirtualClustersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_network_rules = VirtualNetworkRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.extended_database_blob_auditing_policies = ExtendedDatabaseBlobAuditingPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.extended_server_blob_auditing_policies = ExtendedServerBlobAuditingPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_blob_auditing_policies = ServerBlobAuditingPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_blob_auditing_policies = DatabaseBlobAuditingPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_vulnerability_assessment_rule_baselines = DatabaseVulnerabilityAssessmentRuleBaselinesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_vulnerability_assessments = DatabaseVulnerabilityAssessmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_agents = JobAgentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_credentials = JobCredentialsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_executions = JobExecutionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.jobs = JobsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_step_executions = JobStepExecutionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_steps = JobStepsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_target_executions = JobTargetExecutionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_target_groups = JobTargetGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_versions = JobVersionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.long_term_retention_backups = LongTermRetentionBackupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.backup_long_term_retention_policies = BackupLongTermRetentionPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_backup_short_term_retention_policies = ManagedBackupShortTermRetentionPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_restorable_dropped_database_backup_short_term_retention_policies = ManagedRestorableDroppedDatabaseBackupShortTermRetentionPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_automatic_tuning = ServerAutomaticTuningOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_dns_aliases = ServerDnsAliasesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_security_alert_policies = ServerSecurityAlertPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.restorable_dropped_managed_databases = RestorableDroppedManagedDatabasesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.restore_points = RestorePointsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_database_security_alert_policies = ManagedDatabaseSecurityAlertPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_server_security_alert_policies = ManagedServerSecurityAlertPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.sensitivity_labels = SensitivityLabelsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_instance_administrators = ManagedInstanceAdministratorsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_operations = DatabaseOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.elastic_pool_operations = ElasticPoolOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.database_vulnerability_assessment_scans = DatabaseVulnerabilityAssessmentScansOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_database_vulnerability_assessment_rule_baselines = ManagedDatabaseVulnerabilityAssessmentRuleBaselinesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_database_vulnerability_assessment_scans = ManagedDatabaseVulnerabilityAssessmentScansOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_database_vulnerability_assessments = ManagedDatabaseVulnerabilityAssessmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.instance_failover_groups = InstanceFailoverGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.backup_short_term_retention_policies = BackupShortTermRetentionPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tde_certificates = TdeCertificatesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_instance_tde_certificates = ManagedInstanceTdeCertificatesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_instance_keys = ManagedInstanceKeysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_instance_encryption_protectors = ManagedInstanceEncryptionProtectorsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.recoverable_managed_databases = RecoverableManagedDatabasesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_instance_vulnerability_assessments = ManagedInstanceVulnerabilityAssessmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_vulnerability_assessments = ServerVulnerabilityAssessmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_database_sensitivity_labels = ManagedDatabaseSensitivityLabelsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.instance_pools = InstancePoolsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.usages = UsagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_instances = ManagedInstancesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.private_link_resources = PrivateLinkResourcesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.servers = ServersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.capabilities = CapabilitiesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.long_term_retention_managed_instance_backups = LongTermRetentionManagedInstanceBackupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_instance_long_term_retention_policies = ManagedInstanceLongTermRetentionPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workload_groups = WorkloadGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workload_classifiers = WorkloadClassifiersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_database_restore_details = ManagedDatabaseRestoreDetailsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_databases = ManagedDatabasesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_azure_ad_administrators = ServerAzureADAdministratorsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_instance_operations = ManagedInstanceOperations(
            self._client, self.config, self._serialize, self._deserialize)
