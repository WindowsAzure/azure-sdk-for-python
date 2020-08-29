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

from ._configuration import SecurityCenterConfiguration
from .operations import ComplianceResultsOperations
from .operations import PricingsOperations
from .operations import AlertsOperations
from .operations import SettingsOperations
from .operations import AdvancedThreatProtectionOperations
from .operations import DeviceSecurityGroupsOperations
from .operations import IotSecuritySolutionOperations
from .operations import IotSecuritySolutionAnalyticsOperations
from .operations import IotSecuritySolutionsAnalyticsAggregatedAlertOperations
from .operations import IotSecuritySolutionsAnalyticsRecommendationOperations
from .operations import IotAlertTypesOperations
from .operations import IotAlertsOperations
from .operations import IotRecommendationTypesOperations
from .operations import IotRecommendationsOperations
from .operations import LocationsOperations
from .operations import Operations
from .operations import TasksOperations
from .operations import AutoProvisioningSettingsOperations
from .operations import CompliancesOperations
from .operations import InformationProtectionPoliciesOperations
from .operations import SecurityContactsOperations
from .operations import WorkspaceSettingsOperations
from .operations import RegulatoryComplianceStandardsOperations
from .operations import RegulatoryComplianceControlsOperations
from .operations import RegulatoryComplianceAssessmentsOperations
from .operations import SubAssessmentsOperations
from .operations import AutomationsOperations
from .operations import AlertsSuppressionRulesOperations
from .operations import ServerVulnerabilityAssessmentOperations
from .operations import AssessmentsMetadataOperations
from .operations import AssessmentsOperations
from .operations import AdaptiveApplicationControlsOperations
from .operations import AdaptiveNetworkHardeningsOperations
from .operations import AllowedConnectionsOperations
from .operations import TopologyOperations
from .operations import JitNetworkAccessPoliciesOperations
from .operations import DiscoveredSecuritySolutionsOperations
from .operations import SecuritySolutionsReferenceDataOperations
from .operations import ExternalSecuritySolutionsOperations
from .operations import SecureScoresOperations
from .operations import SecureScoreControlsOperations
from .operations import SecureScoreControlDefinitionsOperations
from .operations import SecuritySolutionsOperations
from .operations import ConnectorsOperations
from .operations import IotDefenderSettingsOperations
from .operations import IotSensorsOperations
from . import models


class SecurityCenter(SDKClient):
    """API spec for Microsoft.Security (Azure Security Center) resource provider

    :ivar config: Configuration for client.
    :vartype config: SecurityCenterConfiguration

    :ivar compliance_results: ComplianceResults operations
    :vartype compliance_results: azure.mgmt.security.operations.ComplianceResultsOperations
    :ivar pricings: Pricings operations
    :vartype pricings: azure.mgmt.security.operations.PricingsOperations
    :ivar alerts: Alerts operations
    :vartype alerts: azure.mgmt.security.operations.AlertsOperations
    :ivar settings: Settings operations
    :vartype settings: azure.mgmt.security.operations.SettingsOperations
    :ivar advanced_threat_protection: AdvancedThreatProtection operations
    :vartype advanced_threat_protection: azure.mgmt.security.operations.AdvancedThreatProtectionOperations
    :ivar device_security_groups: DeviceSecurityGroups operations
    :vartype device_security_groups: azure.mgmt.security.operations.DeviceSecurityGroupsOperations
    :ivar iot_security_solution: IotSecuritySolution operations
    :vartype iot_security_solution: azure.mgmt.security.operations.IotSecuritySolutionOperations
    :ivar iot_security_solution_analytics: IotSecuritySolutionAnalytics operations
    :vartype iot_security_solution_analytics: azure.mgmt.security.operations.IotSecuritySolutionAnalyticsOperations
    :ivar iot_security_solutions_analytics_aggregated_alert: IotSecuritySolutionsAnalyticsAggregatedAlert operations
    :vartype iot_security_solutions_analytics_aggregated_alert: azure.mgmt.security.operations.IotSecuritySolutionsAnalyticsAggregatedAlertOperations
    :ivar iot_security_solutions_analytics_recommendation: IotSecuritySolutionsAnalyticsRecommendation operations
    :vartype iot_security_solutions_analytics_recommendation: azure.mgmt.security.operations.IotSecuritySolutionsAnalyticsRecommendationOperations
    :ivar iot_alert_types: IotAlertTypes operations
    :vartype iot_alert_types: azure.mgmt.security.operations.IotAlertTypesOperations
    :ivar iot_alerts: IotAlerts operations
    :vartype iot_alerts: azure.mgmt.security.operations.IotAlertsOperations
    :ivar iot_recommendation_types: IotRecommendationTypes operations
    :vartype iot_recommendation_types: azure.mgmt.security.operations.IotRecommendationTypesOperations
    :ivar iot_recommendations: IotRecommendations operations
    :vartype iot_recommendations: azure.mgmt.security.operations.IotRecommendationsOperations
    :ivar locations: Locations operations
    :vartype locations: azure.mgmt.security.operations.LocationsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.security.operations.Operations
    :ivar tasks: Tasks operations
    :vartype tasks: azure.mgmt.security.operations.TasksOperations
    :ivar auto_provisioning_settings: AutoProvisioningSettings operations
    :vartype auto_provisioning_settings: azure.mgmt.security.operations.AutoProvisioningSettingsOperations
    :ivar compliances: Compliances operations
    :vartype compliances: azure.mgmt.security.operations.CompliancesOperations
    :ivar information_protection_policies: InformationProtectionPolicies operations
    :vartype information_protection_policies: azure.mgmt.security.operations.InformationProtectionPoliciesOperations
    :ivar security_contacts: SecurityContacts operations
    :vartype security_contacts: azure.mgmt.security.operations.SecurityContactsOperations
    :ivar workspace_settings: WorkspaceSettings operations
    :vartype workspace_settings: azure.mgmt.security.operations.WorkspaceSettingsOperations
    :ivar regulatory_compliance_standards: RegulatoryComplianceStandards operations
    :vartype regulatory_compliance_standards: azure.mgmt.security.operations.RegulatoryComplianceStandardsOperations
    :ivar regulatory_compliance_controls: RegulatoryComplianceControls operations
    :vartype regulatory_compliance_controls: azure.mgmt.security.operations.RegulatoryComplianceControlsOperations
    :ivar regulatory_compliance_assessments: RegulatoryComplianceAssessments operations
    :vartype regulatory_compliance_assessments: azure.mgmt.security.operations.RegulatoryComplianceAssessmentsOperations
    :ivar sub_assessments: SubAssessments operations
    :vartype sub_assessments: azure.mgmt.security.operations.SubAssessmentsOperations
    :ivar automations: Automations operations
    :vartype automations: azure.mgmt.security.operations.AutomationsOperations
    :ivar alerts_suppression_rules: AlertsSuppressionRules operations
    :vartype alerts_suppression_rules: azure.mgmt.security.operations.AlertsSuppressionRulesOperations
    :ivar server_vulnerability_assessment: ServerVulnerabilityAssessment operations
    :vartype server_vulnerability_assessment: azure.mgmt.security.operations.ServerVulnerabilityAssessmentOperations
    :ivar assessments_metadata: AssessmentsMetadata operations
    :vartype assessments_metadata: azure.mgmt.security.operations.AssessmentsMetadataOperations
    :ivar assessments: Assessments operations
    :vartype assessments: azure.mgmt.security.operations.AssessmentsOperations
    :ivar adaptive_application_controls: AdaptiveApplicationControls operations
    :vartype adaptive_application_controls: azure.mgmt.security.operations.AdaptiveApplicationControlsOperations
    :ivar adaptive_network_hardenings: AdaptiveNetworkHardenings operations
    :vartype adaptive_network_hardenings: azure.mgmt.security.operations.AdaptiveNetworkHardeningsOperations
    :ivar allowed_connections: AllowedConnections operations
    :vartype allowed_connections: azure.mgmt.security.operations.AllowedConnectionsOperations
    :ivar topology: Topology operations
    :vartype topology: azure.mgmt.security.operations.TopologyOperations
    :ivar jit_network_access_policies: JitNetworkAccessPolicies operations
    :vartype jit_network_access_policies: azure.mgmt.security.operations.JitNetworkAccessPoliciesOperations
    :ivar discovered_security_solutions: DiscoveredSecuritySolutions operations
    :vartype discovered_security_solutions: azure.mgmt.security.operations.DiscoveredSecuritySolutionsOperations
    :ivar security_solutions_reference_data: SecuritySolutionsReferenceData operations
    :vartype security_solutions_reference_data: azure.mgmt.security.operations.SecuritySolutionsReferenceDataOperations
    :ivar external_security_solutions: ExternalSecuritySolutions operations
    :vartype external_security_solutions: azure.mgmt.security.operations.ExternalSecuritySolutionsOperations
    :ivar secure_scores: SecureScores operations
    :vartype secure_scores: azure.mgmt.security.operations.SecureScoresOperations
    :ivar secure_score_controls: SecureScoreControls operations
    :vartype secure_score_controls: azure.mgmt.security.operations.SecureScoreControlsOperations
    :ivar secure_score_control_definitions: SecureScoreControlDefinitions operations
    :vartype secure_score_control_definitions: azure.mgmt.security.operations.SecureScoreControlDefinitionsOperations
    :ivar security_solutions: SecuritySolutions operations
    :vartype security_solutions: azure.mgmt.security.operations.SecuritySolutionsOperations
    :ivar connectors: Connectors operations
    :vartype connectors: azure.mgmt.security.operations.ConnectorsOperations
    :ivar iot_defender_settings: IotDefenderSettings operations
    :vartype iot_defender_settings: azure.mgmt.security.operations.IotDefenderSettingsOperations
    :ivar iot_sensors: IotSensors operations
    :vartype iot_sensors: azure.mgmt.security.operations.IotSensorsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure subscription ID
    :type subscription_id: str
    :param asc_location: The location where ASC stores the data of the
     subscription. can be retrieved from Get locations
    :type asc_location: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, asc_location, base_url=None):

        self.config = SecurityCenterConfiguration(credentials, subscription_id, asc_location, base_url)
        super(SecurityCenter, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.compliance_results = ComplianceResultsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.pricings = PricingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.alerts = AlertsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.settings = SettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.advanced_threat_protection = AdvancedThreatProtectionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.device_security_groups = DeviceSecurityGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_security_solution = IotSecuritySolutionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_security_solution_analytics = IotSecuritySolutionAnalyticsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_security_solutions_analytics_aggregated_alert = IotSecuritySolutionsAnalyticsAggregatedAlertOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_security_solutions_analytics_recommendation = IotSecuritySolutionsAnalyticsRecommendationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_alert_types = IotAlertTypesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_alerts = IotAlertsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_recommendation_types = IotRecommendationTypesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_recommendations = IotRecommendationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.locations = LocationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tasks = TasksOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.auto_provisioning_settings = AutoProvisioningSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.compliances = CompliancesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.information_protection_policies = InformationProtectionPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.security_contacts = SecurityContactsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workspace_settings = WorkspaceSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.regulatory_compliance_standards = RegulatoryComplianceStandardsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.regulatory_compliance_controls = RegulatoryComplianceControlsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.regulatory_compliance_assessments = RegulatoryComplianceAssessmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.sub_assessments = SubAssessmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.automations = AutomationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.alerts_suppression_rules = AlertsSuppressionRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.server_vulnerability_assessment = ServerVulnerabilityAssessmentOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.assessments_metadata = AssessmentsMetadataOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.assessments = AssessmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.adaptive_application_controls = AdaptiveApplicationControlsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.adaptive_network_hardenings = AdaptiveNetworkHardeningsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.allowed_connections = AllowedConnectionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.topology = TopologyOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.jit_network_access_policies = JitNetworkAccessPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.discovered_security_solutions = DiscoveredSecuritySolutionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.security_solutions_reference_data = SecuritySolutionsReferenceDataOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.external_security_solutions = ExternalSecuritySolutionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.secure_scores = SecureScoresOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.secure_score_controls = SecureScoreControlsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.secure_score_control_definitions = SecureScoreControlDefinitionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.security_solutions = SecuritySolutionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.connectors = ConnectorsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_defender_settings = IotDefenderSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_sensors = IotSensorsOperations(
            self._client, self.config, self._serialize, self._deserialize)
