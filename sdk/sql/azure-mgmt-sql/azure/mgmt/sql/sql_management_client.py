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
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.recoverable_databases_operations import RecoverableDatabasesOperations
from .operations.restorable_dropped_databases_operations import RestorableDroppedDatabasesOperations
from .operations.servers_operations import ServersOperations
from .operations.server_connection_policies_operations import ServerConnectionPoliciesOperations
from .operations.database_threat_detection_policies_operations import DatabaseThreatDetectionPoliciesOperations
from .operations.data_masking_policies_operations import DataMaskingPoliciesOperations
from .operations.data_masking_rules_operations import DataMaskingRulesOperations
from .operations.firewall_rules_operations import FirewallRulesOperations
from .operations.geo_backup_policies_operations import GeoBackupPoliciesOperations
from .operations.databases_operations import DatabasesOperations
from .operations.elastic_pools_operations import ElasticPoolsOperations
from .operations.recommended_elastic_pools_operations import RecommendedElasticPoolsOperations
from .operations.replication_links_operations import ReplicationLinksOperations
from .operations.server_azure_ad_administrators_operations import ServerAzureADAdministratorsOperations
from .operations.server_communication_links_operations import ServerCommunicationLinksOperations
from .operations.service_objectives_operations import ServiceObjectivesOperations
from .operations.elastic_pool_activities_operations import ElasticPoolActivitiesOperations
from .operations.elastic_pool_database_activities_operations import ElasticPoolDatabaseActivitiesOperations
from .operations.service_tier_advisors_operations import ServiceTierAdvisorsOperations
from .operations.transparent_data_encryptions_operations import TransparentDataEncryptionsOperations
from .operations.transparent_data_encryption_activities_operations import TransparentDataEncryptionActivitiesOperations
from .operations.server_usages_operations import ServerUsagesOperations
from .operations.database_usages_operations import DatabaseUsagesOperations
from .operations.database_automatic_tuning_operations import DatabaseAutomaticTuningOperations
from .operations.encryption_protectors_operations import EncryptionProtectorsOperations
from .operations.failover_groups_operations import FailoverGroupsOperations
from .operations.operations import Operations
from .operations.server_keys_operations import ServerKeysOperations
from .operations.sync_agents_operations import SyncAgentsOperations
from .operations.sync_groups_operations import SyncGroupsOperations
from .operations.sync_members_operations import SyncMembersOperations
from .operations.subscription_usages_operations import SubscriptionUsagesOperations
from .operations.virtual_clusters_operations import VirtualClustersOperations
from .operations.virtual_network_rules_operations import VirtualNetworkRulesOperations
from .operations.extended_database_blob_auditing_policies_operations import ExtendedDatabaseBlobAuditingPoliciesOperations
from .operations.extended_server_blob_auditing_policies_operations import ExtendedServerBlobAuditingPoliciesOperations
from .operations.server_blob_auditing_policies_operations import ServerBlobAuditingPoliciesOperations
from .operations.database_blob_auditing_policies_operations import DatabaseBlobAuditingPoliciesOperations
from .operations.database_vulnerability_assessment_rule_baselines_operations import DatabaseVulnerabilityAssessmentRuleBaselinesOperations
from .operations.database_vulnerability_assessments_operations import DatabaseVulnerabilityAssessmentsOperations
from .operations.job_agents_operations import JobAgentsOperations
from .operations.job_credentials_operations import JobCredentialsOperations
from .operations.job_executions_operations import JobExecutionsOperations
from .operations.jobs_operations import JobsOperations
from .operations.job_step_executions_operations import JobStepExecutionsOperations
from .operations.job_steps_operations import JobStepsOperations
from .operations.job_target_executions_operations import JobTargetExecutionsOperations
from .operations.job_target_groups_operations import JobTargetGroupsOperations
from .operations.job_versions_operations import JobVersionsOperations
from .operations.long_term_retention_backups_operations import LongTermRetentionBackupsOperations
from .operations.backup_long_term_retention_policies_operations import BackupLongTermRetentionPoliciesOperations
from .operations.managed_backup_short_term_retention_policies_operations import ManagedBackupShortTermRetentionPoliciesOperations
from .operations.managed_databases_operations import ManagedDatabasesOperations
from .operations.managed_restorable_dropped_database_backup_short_term_retention_policies_operations import ManagedRestorableDroppedDatabaseBackupShortTermRetentionPoliciesOperations
from .operations.server_automatic_tuning_operations import ServerAutomaticTuningOperations
from .operations.server_dns_aliases_operations import ServerDnsAliasesOperations
from .operations.server_security_alert_policies_operations import ServerSecurityAlertPoliciesOperations
from .operations.restorable_dropped_managed_databases_operations import RestorableDroppedManagedDatabasesOperations
from .operations.restore_points_operations import RestorePointsOperations
from .operations.managed_database_security_alert_policies_operations import ManagedDatabaseSecurityAlertPoliciesOperations
from .operations.managed_server_security_alert_policies_operations import ManagedServerSecurityAlertPoliciesOperations
from .operations.sensitivity_labels_operations import SensitivityLabelsOperations
from .operations.managed_instance_administrators_operations import ManagedInstanceAdministratorsOperations
from .operations.database_operations import DatabaseOperations
from .operations.elastic_pool_operations import ElasticPoolOperations
from .operations.capabilities_operations import CapabilitiesOperations
from .operations.database_vulnerability_assessment_scans_operations import DatabaseVulnerabilityAssessmentScansOperations
from .operations.managed_database_vulnerability_assessment_rule_baselines_operations import ManagedDatabaseVulnerabilityAssessmentRuleBaselinesOperations
from .operations.managed_database_vulnerability_assessment_scans_operations import ManagedDatabaseVulnerabilityAssessmentScansOperations
from .operations.managed_database_vulnerability_assessments_operations import ManagedDatabaseVulnerabilityAssessmentsOperations
from .operations.instance_failover_groups_operations import InstanceFailoverGroupsOperations
from .operations.backup_short_term_retention_policies_operations import BackupShortTermRetentionPoliciesOperations
from .operations.tde_certificates_operations import TdeCertificatesOperations
from .operations.managed_instance_tde_certificates_operations import ManagedInstanceTdeCertificatesOperations
from .operations.managed_instance_keys_operations import ManagedInstanceKeysOperations
from .operations.managed_instance_encryption_protectors_operations import ManagedInstanceEncryptionProtectorsOperations
from .operations.recoverable_managed_databases_operations import RecoverableManagedDatabasesOperations
from .operations.managed_instance_vulnerability_assessments_operations import ManagedInstanceVulnerabilityAssessmentsOperations
from .operations.server_vulnerability_assessments_operations import ServerVulnerabilityAssessmentsOperations
from .operations.managed_database_sensitivity_labels_operations import ManagedDatabaseSensitivityLabelsOperations
from .operations.instance_pools_operations import InstancePoolsOperations
from .operations.usages_operations import UsagesOperations
from .operations.managed_instances_operations import ManagedInstancesOperations
from . import models


class SqlManagementClientConfiguration(AzureConfiguration):
    """Configuration for SqlManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

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

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(SqlManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-sql/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class SqlManagementClient(SDKClient):
    """The Azure SQL Database management API provides a RESTful set of web services that interact with Azure SQL Database services to manage your databases. The API enables you to create, retrieve, update, and delete databases.

    :ivar config: Configuration for client.
    :vartype config: SqlManagementClientConfiguration

    :ivar recoverable_databases: RecoverableDatabases operations
    :vartype recoverable_databases: azure.mgmt.sql.operations.RecoverableDatabasesOperations
    :ivar restorable_dropped_databases: RestorableDroppedDatabases operations
    :vartype restorable_dropped_databases: azure.mgmt.sql.operations.RestorableDroppedDatabasesOperations
    :ivar servers: Servers operations
    :vartype servers: azure.mgmt.sql.operations.ServersOperations
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
    :ivar server_azure_ad_administrators: ServerAzureADAdministrators operations
    :vartype server_azure_ad_administrators: azure.mgmt.sql.operations.ServerAzureADAdministratorsOperations
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
    :ivar managed_databases: ManagedDatabases operations
    :vartype managed_databases: azure.mgmt.sql.operations.ManagedDatabasesOperations
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
    :ivar capabilities: Capabilities operations
    :vartype capabilities: azure.mgmt.sql.operations.CapabilitiesOperations
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
        self.servers = ServersOperations(
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
        self.server_azure_ad_administrators = ServerAzureADAdministratorsOperations(
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
        self.managed_databases = ManagedDatabasesOperations(
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
        self.capabilities = CapabilitiesOperations(
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
