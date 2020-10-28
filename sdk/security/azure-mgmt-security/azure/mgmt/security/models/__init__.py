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
    from ._models_py3 import AadConnectivityState1
    from ._models_py3 import AadExternalSecuritySolution
    from ._models_py3 import AadSolutionProperties
    from ._models_py3 import ActiveConnectionsNotInAllowedRange
    from ._models_py3 import AdaptiveApplicationControlGroup
    from ._models_py3 import AdaptiveApplicationControlGroups
    from ._models_py3 import AdaptiveApplicationControlIssueSummary
    from ._models_py3 import AdaptiveNetworkHardening
    from ._models_py3 import AdaptiveNetworkHardeningEnforceRequest
    from ._models_py3 import AdditionalData
    from ._models_py3 import AdvancedThreatProtectionSetting
    from ._models_py3 import Alert
    from ._models_py3 import AlertEntity
    from ._models_py3 import AlertsSuppressionRule
    from ._models_py3 import AllowedConnectionsResource
    from ._models_py3 import AllowlistCustomAlertRule
    from ._models_py3 import AmqpC2DMessagesNotInAllowedRange
    from ._models_py3 import AmqpC2DRejectedMessagesNotInAllowedRange
    from ._models_py3 import AmqpD2CMessagesNotInAllowedRange
    from ._models_py3 import AscLocation
    from ._models_py3 import AssessmentLinks
    from ._models_py3 import AssessmentStatus
    from ._models_py3 import AtaExternalSecuritySolution
    from ._models_py3 import AtaSolutionProperties
    from ._models_py3 import AuthenticationDetailsProperties
    from ._models_py3 import Automation
    from ._models_py3 import AutomationAction
    from ._models_py3 import AutomationActionEventHub
    from ._models_py3 import AutomationActionLogicApp
    from ._models_py3 import AutomationActionWorkspace
    from ._models_py3 import AutomationRuleSet
    from ._models_py3 import AutomationScope
    from ._models_py3 import AutomationSource
    from ._models_py3 import AutomationTriggeringRule
    from ._models_py3 import AutomationValidationStatus
    from ._models_py3 import AutoProvisioningSetting
    from ._models_py3 import AwAssumeRoleAuthenticationDetailsProperties
    from ._models_py3 import AwsCredsAuthenticationDetailsProperties
    from ._models_py3 import AzureResourceDetails
    from ._models_py3 import AzureResourceIdentifier
    from ._models_py3 import AzureResourceLink
    from ._models_py3 import AzureTrackedResourceLocation
    from ._models_py3 import Baseline
    from ._models_py3 import BaselineAdjustedResult
    from ._models_py3 import BenchmarkReference
    from ._models_py3 import CefExternalSecuritySolution
    from ._models_py3 import CefSolutionProperties
    from ._models_py3 import Compliance
    from ._models_py3 import ComplianceResult
    from ._models_py3 import ComplianceSegment
    from ._models_py3 import ConnectableResource
    from ._models_py3 import ConnectedResource
    from ._models_py3 import ConnectedWorkspace
    from ._models_py3 import ConnectionToIpNotAllowed
    from ._models_py3 import ConnectorSetting
    from ._models_py3 import ContainerRegistryVulnerabilityProperties
    from ._models_py3 import CustomAlertRule
    from ._models_py3 import CVE
    from ._models_py3 import CVSS
    from ._models_py3 import DataExportSettings
    from ._models_py3 import DenylistCustomAlertRule
    from ._models_py3 import Device
    from ._models_py3 import DeviceSecurityGroup
    from ._models_py3 import DirectMethodInvokesNotInAllowedRange
    from ._models_py3 import DiscoveredSecuritySolution
    from ._models_py3 import EffectiveNetworkSecurityGroups
    from ._models_py3 import ETag
    from ._models_py3 import ExternalSecuritySolution
    from ._models_py3 import ExternalSecuritySolutionKind1
    from ._models_py3 import ExternalSecuritySolutionProperties
    from ._models_py3 import FailedLocalLoginsNotInAllowedRange
    from ._models_py3 import FileUploadsNotInAllowedRange
    from ._models_py3 import Firmware
    from ._models_py3 import GcpCredentialsDetailsProperties
    from ._models_py3 import HttpC2DMessagesNotInAllowedRange
    from ._models_py3 import HttpC2DRejectedMessagesNotInAllowedRange
    from ._models_py3 import HttpD2CMessagesNotInAllowedRange
    from ._models_py3 import HybridComputeSettingsProperties
    from ._models_py3 import InformationProtectionKeyword
    from ._models_py3 import InformationProtectionPolicy
    from ._models_py3 import InformationType
    from ._models_py3 import IotAlert
    from ._models_py3 import IotAlertType
    from ._models_py3 import IotAlertTypeList
    from ._models_py3 import IotDefenderSettingsList
    from ._models_py3 import IotDefenderSettingsModel
    from ._models_py3 import IotRecommendation
    from ._models_py3 import IotRecommendationType
    from ._models_py3 import IotRecommendationTypeList
    from ._models_py3 import IoTSecurityAggregatedAlert
    from ._models_py3 import IoTSecurityAggregatedAlertPropertiesTopDevicesListItem
    from ._models_py3 import IoTSecurityAggregatedRecommendation
    from ._models_py3 import IoTSecurityAlertedDevice
    from ._models_py3 import IoTSecurityDeviceAlert
    from ._models_py3 import IoTSecurityDeviceRecommendation
    from ._models_py3 import IoTSecuritySolutionAnalyticsModel
    from ._models_py3 import IoTSecuritySolutionAnalyticsModelList
    from ._models_py3 import IoTSecuritySolutionAnalyticsModelPropertiesDevicesMetricsItem
    from ._models_py3 import IoTSecuritySolutionModel
    from ._models_py3 import IotSensor
    from ._models_py3 import IotSensorsList
    from ._models_py3 import IoTSeverityMetrics
    from ._models_py3 import IpAddress
    from ._models_py3 import JitNetworkAccessPolicy
    from ._models_py3 import JitNetworkAccessPolicyInitiatePort
    from ._models_py3 import JitNetworkAccessPolicyInitiateRequest
    from ._models_py3 import JitNetworkAccessPolicyInitiateVirtualMachine
    from ._models_py3 import JitNetworkAccessPolicyVirtualMachine
    from ._models_py3 import JitNetworkAccessPortRule
    from ._models_py3 import JitNetworkAccessRequest
    from ._models_py3 import JitNetworkAccessRequestPort
    from ._models_py3 import JitNetworkAccessRequestVirtualMachine
    from ._models_py3 import Kind
    from ._models_py3 import ListCustomAlertRule
    from ._models_py3 import LocalUserNotAllowed
    from ._models_py3 import Location
    from ._models_py3 import LogAnalyticsIdentifier
    from ._models_py3 import MacAddress
    from ._models_py3 import MqttC2DMessagesNotInAllowedRange
    from ._models_py3 import MqttC2DRejectedMessagesNotInAllowedRange
    from ._models_py3 import MqttD2CMessagesNotInAllowedRange
    from ._models_py3 import NetworkInterface
    from ._models_py3 import OnPremiseIotSensor
    from ._models_py3 import OnPremiseIotSensorsList
    from ._models_py3 import OnPremiseResourceDetails
    from ._models_py3 import OnPremiseSqlResourceDetails
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import PackageDownloadInfo
    from ._models_py3 import PackageDownloads
    from ._models_py3 import PackageDownloadsCentralManager
    from ._models_py3 import PackageDownloadsCentralManagerFull
    from ._models_py3 import PackageDownloadsCentralManagerFullOvf
    from ._models_py3 import PackageDownloadsSensor
    from ._models_py3 import PackageDownloadsSensorFull
    from ._models_py3 import PackageDownloadsSensorFullOvf
    from ._models_py3 import PackageDownloadsThreatIntelligence
    from ._models_py3 import PathRecommendation
    from ._models_py3 import Pricing
    from ._models_py3 import PricingList
    from ._models_py3 import ProcessNotAllowed
    from ._models_py3 import ProtectionMode
    from ._models_py3 import Protocol1
    from ._models_py3 import ProxyServerProperties
    from ._models_py3 import PublisherInfo
    from ._models_py3 import QueryCheck
    from ._models_py3 import QueuePurgesNotInAllowedRange
    from ._models_py3 import RecommendationConfigurationProperties
    from ._models_py3 import RegulatoryComplianceAssessment
    from ._models_py3 import RegulatoryComplianceControl
    from ._models_py3 import RegulatoryComplianceStandard
    from ._models_py3 import Remediation
    from ._models_py3 import Resource
    from ._models_py3 import ResourceDetails
    from ._models_py3 import ResourceIdentifier
    from ._models_py3 import Rule
    from ._models_py3 import RuleResults
    from ._models_py3 import RuleResultsInput
    from ._models_py3 import RuleResultsProperties
    from ._models_py3 import RulesResults
    from ._models_py3 import RulesResultsInput
    from ._models_py3 import Scan
    from ._models_py3 import ScanProperties
    from ._models_py3 import ScanResult
    from ._models_py3 import ScanResultProperties
    from ._models_py3 import ScanResults
    from ._models_py3 import Scans
    from ._models_py3 import ScopeElement
    from ._models_py3 import SecureScoreControlDefinitionItem
    from ._models_py3 import SecureScoreControlDefinitionSource
    from ._models_py3 import SecureScoreControlDetails
    from ._models_py3 import SecureScoreControlScore
    from ._models_py3 import SecureScoreItem
    from ._models_py3 import SecurityAssessment
    from ._models_py3 import SecurityAssessmentMetadata
    from ._models_py3 import SecurityAssessmentMetadataPartnerData
    from ._models_py3 import SecurityAssessmentMetadataProperties
    from ._models_py3 import SecurityAssessmentPartnerData
    from ._models_py3 import SecurityContact
    from ._models_py3 import SecuritySolution
    from ._models_py3 import SecuritySolutionsReferenceData
    from ._models_py3 import SecuritySolutionsReferenceDataList
    from ._models_py3 import SecuritySubAssessment
    from ._models_py3 import SecurityTask
    from ._models_py3 import SecurityTaskParameters
    from ._models_py3 import SensitivityLabel
    from ._models_py3 import ServerVulnerabilityAssessment
    from ._models_py3 import ServerVulnerabilityAssessmentsList
    from ._models_py3 import ServerVulnerabilityProperties
    from ._models_py3 import ServicePrincipalProperties
    from ._models_py3 import Setting
    from ._models_py3 import SettingResource
    from ._models_py3 import SqlServerVulnerabilityProperties
    from ._models_py3 import SubAssessmentStatus
    from ._models_py3 import SuppressionAlertsScope
    from ._models_py3 import Tags
    from ._models_py3 import TagsResource
    from ._models_py3 import ThresholdCustomAlertRule
    from ._models_py3 import TimeWindowCustomAlertRule
    from ._models_py3 import TopologyResource
    from ._models_py3 import TopologySingleResource
    from ._models_py3 import TopologySingleResourceChild
    from ._models_py3 import TopologySingleResourceParent
    from ._models_py3 import TrackedResource
    from ._models_py3 import TwinUpdatesNotInAllowedRange
    from ._models_py3 import UnauthorizedOperationsNotInAllowedRange
    from ._models_py3 import UpdateIotSecuritySolutionData
    from ._models_py3 import UserDefinedResourcesProperties
    from ._models_py3 import UserRecommendation
    from ._models_py3 import VaRule
    from ._models_py3 import VendorReference
    from ._models_py3 import VmRecommendation
    from ._models_py3 import WorkspaceSetting
except (SyntaxError, ImportError):
    from ._models import AadConnectivityState1
    from ._models import AadExternalSecuritySolution
    from ._models import AadSolutionProperties
    from ._models import ActiveConnectionsNotInAllowedRange
    from ._models import AdaptiveApplicationControlGroup
    from ._models import AdaptiveApplicationControlGroups
    from ._models import AdaptiveApplicationControlIssueSummary
    from ._models import AdaptiveNetworkHardening
    from ._models import AdaptiveNetworkHardeningEnforceRequest
    from ._models import AdditionalData
    from ._models import AdvancedThreatProtectionSetting
    from ._models import Alert
    from ._models import AlertEntity
    from ._models import AlertsSuppressionRule
    from ._models import AllowedConnectionsResource
    from ._models import AllowlistCustomAlertRule
    from ._models import AmqpC2DMessagesNotInAllowedRange
    from ._models import AmqpC2DRejectedMessagesNotInAllowedRange
    from ._models import AmqpD2CMessagesNotInAllowedRange
    from ._models import AscLocation
    from ._models import AssessmentLinks
    from ._models import AssessmentStatus
    from ._models import AtaExternalSecuritySolution
    from ._models import AtaSolutionProperties
    from ._models import AuthenticationDetailsProperties
    from ._models import Automation
    from ._models import AutomationAction
    from ._models import AutomationActionEventHub
    from ._models import AutomationActionLogicApp
    from ._models import AutomationActionWorkspace
    from ._models import AutomationRuleSet
    from ._models import AutomationScope
    from ._models import AutomationSource
    from ._models import AutomationTriggeringRule
    from ._models import AutomationValidationStatus
    from ._models import AutoProvisioningSetting
    from ._models import AwAssumeRoleAuthenticationDetailsProperties
    from ._models import AwsCredsAuthenticationDetailsProperties
    from ._models import AzureResourceDetails
    from ._models import AzureResourceIdentifier
    from ._models import AzureResourceLink
    from ._models import AzureTrackedResourceLocation
    from ._models import Baseline
    from ._models import BaselineAdjustedResult
    from ._models import BenchmarkReference
    from ._models import CefExternalSecuritySolution
    from ._models import CefSolutionProperties
    from ._models import Compliance
    from ._models import ComplianceResult
    from ._models import ComplianceSegment
    from ._models import ConnectableResource
    from ._models import ConnectedResource
    from ._models import ConnectedWorkspace
    from ._models import ConnectionToIpNotAllowed
    from ._models import ConnectorSetting
    from ._models import ContainerRegistryVulnerabilityProperties
    from ._models import CustomAlertRule
    from ._models import CVE
    from ._models import CVSS
    from ._models import DataExportSettings
    from ._models import DenylistCustomAlertRule
    from ._models import Device
    from ._models import DeviceSecurityGroup
    from ._models import DirectMethodInvokesNotInAllowedRange
    from ._models import DiscoveredSecuritySolution
    from ._models import EffectiveNetworkSecurityGroups
    from ._models import ETag
    from ._models import ExternalSecuritySolution
    from ._models import ExternalSecuritySolutionKind1
    from ._models import ExternalSecuritySolutionProperties
    from ._models import FailedLocalLoginsNotInAllowedRange
    from ._models import FileUploadsNotInAllowedRange
    from ._models import Firmware
    from ._models import GcpCredentialsDetailsProperties
    from ._models import HttpC2DMessagesNotInAllowedRange
    from ._models import HttpC2DRejectedMessagesNotInAllowedRange
    from ._models import HttpD2CMessagesNotInAllowedRange
    from ._models import HybridComputeSettingsProperties
    from ._models import InformationProtectionKeyword
    from ._models import InformationProtectionPolicy
    from ._models import InformationType
    from ._models import IotAlert
    from ._models import IotAlertType
    from ._models import IotAlertTypeList
    from ._models import IotDefenderSettingsList
    from ._models import IotDefenderSettingsModel
    from ._models import IotRecommendation
    from ._models import IotRecommendationType
    from ._models import IotRecommendationTypeList
    from ._models import IoTSecurityAggregatedAlert
    from ._models import IoTSecurityAggregatedAlertPropertiesTopDevicesListItem
    from ._models import IoTSecurityAggregatedRecommendation
    from ._models import IoTSecurityAlertedDevice
    from ._models import IoTSecurityDeviceAlert
    from ._models import IoTSecurityDeviceRecommendation
    from ._models import IoTSecuritySolutionAnalyticsModel
    from ._models import IoTSecuritySolutionAnalyticsModelList
    from ._models import IoTSecuritySolutionAnalyticsModelPropertiesDevicesMetricsItem
    from ._models import IoTSecuritySolutionModel
    from ._models import IotSensor
    from ._models import IotSensorsList
    from ._models import IoTSeverityMetrics
    from ._models import IpAddress
    from ._models import JitNetworkAccessPolicy
    from ._models import JitNetworkAccessPolicyInitiatePort
    from ._models import JitNetworkAccessPolicyInitiateRequest
    from ._models import JitNetworkAccessPolicyInitiateVirtualMachine
    from ._models import JitNetworkAccessPolicyVirtualMachine
    from ._models import JitNetworkAccessPortRule
    from ._models import JitNetworkAccessRequest
    from ._models import JitNetworkAccessRequestPort
    from ._models import JitNetworkAccessRequestVirtualMachine
    from ._models import Kind
    from ._models import ListCustomAlertRule
    from ._models import LocalUserNotAllowed
    from ._models import Location
    from ._models import LogAnalyticsIdentifier
    from ._models import MacAddress
    from ._models import MqttC2DMessagesNotInAllowedRange
    from ._models import MqttC2DRejectedMessagesNotInAllowedRange
    from ._models import MqttD2CMessagesNotInAllowedRange
    from ._models import NetworkInterface
    from ._models import OnPremiseIotSensor
    from ._models import OnPremiseIotSensorsList
    from ._models import OnPremiseResourceDetails
    from ._models import OnPremiseSqlResourceDetails
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import PackageDownloadInfo
    from ._models import PackageDownloads
    from ._models import PackageDownloadsCentralManager
    from ._models import PackageDownloadsCentralManagerFull
    from ._models import PackageDownloadsCentralManagerFullOvf
    from ._models import PackageDownloadsSensor
    from ._models import PackageDownloadsSensorFull
    from ._models import PackageDownloadsSensorFullOvf
    from ._models import PackageDownloadsThreatIntelligence
    from ._models import PathRecommendation
    from ._models import Pricing
    from ._models import PricingList
    from ._models import ProcessNotAllowed
    from ._models import ProtectionMode
    from ._models import Protocol1
    from ._models import ProxyServerProperties
    from ._models import PublisherInfo
    from ._models import QueryCheck
    from ._models import QueuePurgesNotInAllowedRange
    from ._models import RecommendationConfigurationProperties
    from ._models import RegulatoryComplianceAssessment
    from ._models import RegulatoryComplianceControl
    from ._models import RegulatoryComplianceStandard
    from ._models import Remediation
    from ._models import Resource
    from ._models import ResourceDetails
    from ._models import ResourceIdentifier
    from ._models import Rule
    from ._models import RuleResults
    from ._models import RuleResultsInput
    from ._models import RuleResultsProperties
    from ._models import RulesResults
    from ._models import RulesResultsInput
    from ._models import Scan
    from ._models import ScanProperties
    from ._models import ScanResult
    from ._models import ScanResultProperties
    from ._models import ScanResults
    from ._models import Scans
    from ._models import ScopeElement
    from ._models import SecureScoreControlDefinitionItem
    from ._models import SecureScoreControlDefinitionSource
    from ._models import SecureScoreControlDetails
    from ._models import SecureScoreControlScore
    from ._models import SecureScoreItem
    from ._models import SecurityAssessment
    from ._models import SecurityAssessmentMetadata
    from ._models import SecurityAssessmentMetadataPartnerData
    from ._models import SecurityAssessmentMetadataProperties
    from ._models import SecurityAssessmentPartnerData
    from ._models import SecurityContact
    from ._models import SecuritySolution
    from ._models import SecuritySolutionsReferenceData
    from ._models import SecuritySolutionsReferenceDataList
    from ._models import SecuritySubAssessment
    from ._models import SecurityTask
    from ._models import SecurityTaskParameters
    from ._models import SensitivityLabel
    from ._models import ServerVulnerabilityAssessment
    from ._models import ServerVulnerabilityAssessmentsList
    from ._models import ServerVulnerabilityProperties
    from ._models import ServicePrincipalProperties
    from ._models import Setting
    from ._models import SettingResource
    from ._models import SqlServerVulnerabilityProperties
    from ._models import SubAssessmentStatus
    from ._models import SuppressionAlertsScope
    from ._models import Tags
    from ._models import TagsResource
    from ._models import ThresholdCustomAlertRule
    from ._models import TimeWindowCustomAlertRule
    from ._models import TopologyResource
    from ._models import TopologySingleResource
    from ._models import TopologySingleResourceChild
    from ._models import TopologySingleResourceParent
    from ._models import TrackedResource
    from ._models import TwinUpdatesNotInAllowedRange
    from ._models import UnauthorizedOperationsNotInAllowedRange
    from ._models import UpdateIotSecuritySolutionData
    from ._models import UserDefinedResourcesProperties
    from ._models import UserRecommendation
    from ._models import VaRule
    from ._models import VendorReference
    from ._models import VmRecommendation
    from ._models import WorkspaceSetting
from ._paged_models import AdaptiveNetworkHardeningPaged
from ._paged_models import AlertPaged
from ._paged_models import AlertsSuppressionRulePaged
from ._paged_models import AllowedConnectionsResourcePaged
from ._paged_models import AscLocationPaged
from ._paged_models import AutomationPaged
from ._paged_models import AutoProvisioningSettingPaged
from ._paged_models import CompliancePaged
from ._paged_models import ComplianceResultPaged
from ._paged_models import ConnectorSettingPaged
from ._paged_models import DevicePaged
from ._paged_models import DeviceSecurityGroupPaged
from ._paged_models import DiscoveredSecuritySolutionPaged
from ._paged_models import ExternalSecuritySolutionPaged
from ._paged_models import InformationProtectionPolicyPaged
from ._paged_models import IotAlertPaged
from ._paged_models import IotRecommendationPaged
from ._paged_models import IoTSecurityAggregatedAlertPaged
from ._paged_models import IoTSecurityAggregatedRecommendationPaged
from ._paged_models import IoTSecuritySolutionModelPaged
from ._paged_models import JitNetworkAccessPolicyPaged
from ._paged_models import OperationPaged
from ._paged_models import RegulatoryComplianceAssessmentPaged
from ._paged_models import RegulatoryComplianceControlPaged
from ._paged_models import RegulatoryComplianceStandardPaged
from ._paged_models import SecureScoreControlDefinitionItemPaged
from ._paged_models import SecureScoreControlDetailsPaged
from ._paged_models import SecureScoreItemPaged
from ._paged_models import SecurityAssessmentMetadataPaged
from ._paged_models import SecurityAssessmentPaged
from ._paged_models import SecurityContactPaged
from ._paged_models import SecuritySolutionPaged
from ._paged_models import SecuritySubAssessmentPaged
from ._paged_models import SecurityTaskPaged
from ._paged_models import SettingPaged
from ._paged_models import TopologyResourcePaged
from ._paged_models import WorkspaceSettingPaged
from ._security_center_enums import (
    ResourceStatus,
    PricingTier,
    ValueType,
    SecuritySolutionStatus,
    ExportData,
    DataSource,
    RecommendationType,
    RecommendationConfigStatus,
    UnmaskedIpLoggingStatus,
    ReportedSeverity,
    AlertSeverity,
    AlertIntent,
    RecommendationSeverity,
    AutoProvision,
    Rank,
    AlertNotifications,
    AlertsToAdmins,
    State,
    SubAssessmentStatusCode,
    Severity,
    EventSource,
    PropertyType,
    Operator,
    RuleState,
    Category,
    UserImpact,
    ImplementationEffort,
    Threats,
    AssessmentType,
    AssessmentStatusCode,
    Direction,
    TransportProtocol,
    Intent,
    AlertStatus,
    Protocol,
    Status,
    StatusReason,
    SecurityFamily,
    AadConnectivityState,
    ExternalSecuritySolutionKind,
    ControlType,
    ProvisioningState,
    HybridComputeProvisioningState,
    AuthenticationProvisioningState,
    PermissionProperty,
    VersionKind,
    MacSignificance,
    RelationToIpStatus,
    ManagementState,
    AuthorizationState,
    DeviceCriticality,
    PurdueLevel,
    ProgrammingState,
    ScanningFunctionality,
    DeviceStatus,
    ScanTriggerType,
    ScanState,
    RuleStatus,
    RuleSeverity,
    RuleType,
    ExpandEnum,
    ConnectionType,
    ExpandControlsEnum,
)

__all__ = [
    'AadConnectivityState1',
    'AadExternalSecuritySolution',
    'AadSolutionProperties',
    'ActiveConnectionsNotInAllowedRange',
    'AdaptiveApplicationControlGroup',
    'AdaptiveApplicationControlGroups',
    'AdaptiveApplicationControlIssueSummary',
    'AdaptiveNetworkHardening',
    'AdaptiveNetworkHardeningEnforceRequest',
    'AdditionalData',
    'AdvancedThreatProtectionSetting',
    'Alert',
    'AlertEntity',
    'AlertsSuppressionRule',
    'AllowedConnectionsResource',
    'AllowlistCustomAlertRule',
    'AmqpC2DMessagesNotInAllowedRange',
    'AmqpC2DRejectedMessagesNotInAllowedRange',
    'AmqpD2CMessagesNotInAllowedRange',
    'AscLocation',
    'AssessmentLinks',
    'AssessmentStatus',
    'AtaExternalSecuritySolution',
    'AtaSolutionProperties',
    'AuthenticationDetailsProperties',
    'Automation',
    'AutomationAction',
    'AutomationActionEventHub',
    'AutomationActionLogicApp',
    'AutomationActionWorkspace',
    'AutomationRuleSet',
    'AutomationScope',
    'AutomationSource',
    'AutomationTriggeringRule',
    'AutomationValidationStatus',
    'AutoProvisioningSetting',
    'AwAssumeRoleAuthenticationDetailsProperties',
    'AwsCredsAuthenticationDetailsProperties',
    'AzureResourceDetails',
    'AzureResourceIdentifier',
    'AzureResourceLink',
    'AzureTrackedResourceLocation',
    'Baseline',
    'BaselineAdjustedResult',
    'BenchmarkReference',
    'CefExternalSecuritySolution',
    'CefSolutionProperties',
    'Compliance',
    'ComplianceResult',
    'ComplianceSegment',
    'ConnectableResource',
    'ConnectedResource',
    'ConnectedWorkspace',
    'ConnectionToIpNotAllowed',
    'ConnectorSetting',
    'ContainerRegistryVulnerabilityProperties',
    'CustomAlertRule',
    'CVE',
    'CVSS',
    'DataExportSettings',
    'DenylistCustomAlertRule',
    'Device',
    'DeviceSecurityGroup',
    'DirectMethodInvokesNotInAllowedRange',
    'DiscoveredSecuritySolution',
    'EffectiveNetworkSecurityGroups',
    'ETag',
    'ExternalSecuritySolution',
    'ExternalSecuritySolutionKind1',
    'ExternalSecuritySolutionProperties',
    'FailedLocalLoginsNotInAllowedRange',
    'FileUploadsNotInAllowedRange',
    'Firmware',
    'GcpCredentialsDetailsProperties',
    'HttpC2DMessagesNotInAllowedRange',
    'HttpC2DRejectedMessagesNotInAllowedRange',
    'HttpD2CMessagesNotInAllowedRange',
    'HybridComputeSettingsProperties',
    'InformationProtectionKeyword',
    'InformationProtectionPolicy',
    'InformationType',
    'IotAlert',
    'IotAlertType',
    'IotAlertTypeList',
    'IotDefenderSettingsList',
    'IotDefenderSettingsModel',
    'IotRecommendation',
    'IotRecommendationType',
    'IotRecommendationTypeList',
    'IoTSecurityAggregatedAlert',
    'IoTSecurityAggregatedAlertPropertiesTopDevicesListItem',
    'IoTSecurityAggregatedRecommendation',
    'IoTSecurityAlertedDevice',
    'IoTSecurityDeviceAlert',
    'IoTSecurityDeviceRecommendation',
    'IoTSecuritySolutionAnalyticsModel',
    'IoTSecuritySolutionAnalyticsModelList',
    'IoTSecuritySolutionAnalyticsModelPropertiesDevicesMetricsItem',
    'IoTSecuritySolutionModel',
    'IotSensor',
    'IotSensorsList',
    'IoTSeverityMetrics',
    'IpAddress',
    'JitNetworkAccessPolicy',
    'JitNetworkAccessPolicyInitiatePort',
    'JitNetworkAccessPolicyInitiateRequest',
    'JitNetworkAccessPolicyInitiateVirtualMachine',
    'JitNetworkAccessPolicyVirtualMachine',
    'JitNetworkAccessPortRule',
    'JitNetworkAccessRequest',
    'JitNetworkAccessRequestPort',
    'JitNetworkAccessRequestVirtualMachine',
    'Kind',
    'ListCustomAlertRule',
    'LocalUserNotAllowed',
    'Location',
    'LogAnalyticsIdentifier',
    'MacAddress',
    'MqttC2DMessagesNotInAllowedRange',
    'MqttC2DRejectedMessagesNotInAllowedRange',
    'MqttD2CMessagesNotInAllowedRange',
    'NetworkInterface',
    'OnPremiseIotSensor',
    'OnPremiseIotSensorsList',
    'OnPremiseResourceDetails',
    'OnPremiseSqlResourceDetails',
    'Operation',
    'OperationDisplay',
    'PackageDownloadInfo',
    'PackageDownloads',
    'PackageDownloadsCentralManager',
    'PackageDownloadsCentralManagerFull',
    'PackageDownloadsCentralManagerFullOvf',
    'PackageDownloadsSensor',
    'PackageDownloadsSensorFull',
    'PackageDownloadsSensorFullOvf',
    'PackageDownloadsThreatIntelligence',
    'PathRecommendation',
    'Pricing',
    'PricingList',
    'ProcessNotAllowed',
    'ProtectionMode',
    'Protocol1',
    'ProxyServerProperties',
    'PublisherInfo',
    'QueryCheck',
    'QueuePurgesNotInAllowedRange',
    'RecommendationConfigurationProperties',
    'RegulatoryComplianceAssessment',
    'RegulatoryComplianceControl',
    'RegulatoryComplianceStandard',
    'Remediation',
    'Resource',
    'ResourceDetails',
    'ResourceIdentifier',
    'Rule',
    'RuleResults',
    'RuleResultsInput',
    'RuleResultsProperties',
    'RulesResults',
    'RulesResultsInput',
    'Scan',
    'ScanProperties',
    'ScanResult',
    'ScanResultProperties',
    'ScanResults',
    'Scans',
    'ScopeElement',
    'SecureScoreControlDefinitionItem',
    'SecureScoreControlDefinitionSource',
    'SecureScoreControlDetails',
    'SecureScoreControlScore',
    'SecureScoreItem',
    'SecurityAssessment',
    'SecurityAssessmentMetadata',
    'SecurityAssessmentMetadataPartnerData',
    'SecurityAssessmentMetadataProperties',
    'SecurityAssessmentPartnerData',
    'SecurityContact',
    'SecuritySolution',
    'SecuritySolutionsReferenceData',
    'SecuritySolutionsReferenceDataList',
    'SecuritySubAssessment',
    'SecurityTask',
    'SecurityTaskParameters',
    'SensitivityLabel',
    'ServerVulnerabilityAssessment',
    'ServerVulnerabilityAssessmentsList',
    'ServerVulnerabilityProperties',
    'ServicePrincipalProperties',
    'Setting',
    'SettingResource',
    'SqlServerVulnerabilityProperties',
    'SubAssessmentStatus',
    'SuppressionAlertsScope',
    'Tags',
    'TagsResource',
    'ThresholdCustomAlertRule',
    'TimeWindowCustomAlertRule',
    'TopologyResource',
    'TopologySingleResource',
    'TopologySingleResourceChild',
    'TopologySingleResourceParent',
    'TrackedResource',
    'TwinUpdatesNotInAllowedRange',
    'UnauthorizedOperationsNotInAllowedRange',
    'UpdateIotSecuritySolutionData',
    'UserDefinedResourcesProperties',
    'UserRecommendation',
    'VaRule',
    'VendorReference',
    'VmRecommendation',
    'WorkspaceSetting',
    'ComplianceResultPaged',
    'SettingPaged',
    'DeviceSecurityGroupPaged',
    'IoTSecuritySolutionModelPaged',
    'IoTSecurityAggregatedAlertPaged',
    'IoTSecurityAggregatedRecommendationPaged',
    'IotAlertPaged',
    'IotRecommendationPaged',
    'AscLocationPaged',
    'OperationPaged',
    'SecurityTaskPaged',
    'AutoProvisioningSettingPaged',
    'CompliancePaged',
    'InformationProtectionPolicyPaged',
    'SecurityContactPaged',
    'WorkspaceSettingPaged',
    'RegulatoryComplianceStandardPaged',
    'RegulatoryComplianceControlPaged',
    'RegulatoryComplianceAssessmentPaged',
    'SecuritySubAssessmentPaged',
    'AutomationPaged',
    'AlertsSuppressionRulePaged',
    'SecurityAssessmentMetadataPaged',
    'SecurityAssessmentPaged',
    'AdaptiveNetworkHardeningPaged',
    'AllowedConnectionsResourcePaged',
    'TopologyResourcePaged',
    'AlertPaged',
    'JitNetworkAccessPolicyPaged',
    'DiscoveredSecuritySolutionPaged',
    'ExternalSecuritySolutionPaged',
    'SecureScoreItemPaged',
    'SecureScoreControlDetailsPaged',
    'SecureScoreControlDefinitionItemPaged',
    'SecuritySolutionPaged',
    'ConnectorSettingPaged',
    'DevicePaged',
    'ResourceStatus',
    'PricingTier',
    'ValueType',
    'SecuritySolutionStatus',
    'ExportData',
    'DataSource',
    'RecommendationType',
    'RecommendationConfigStatus',
    'UnmaskedIpLoggingStatus',
    'ReportedSeverity',
    'AlertSeverity',
    'AlertIntent',
    'RecommendationSeverity',
    'AutoProvision',
    'Rank',
    'AlertNotifications',
    'AlertsToAdmins',
    'State',
    'SubAssessmentStatusCode',
    'Severity',
    'EventSource',
    'PropertyType',
    'Operator',
    'RuleState',
    'Category',
    'UserImpact',
    'ImplementationEffort',
    'Threats',
    'AssessmentType',
    'AssessmentStatusCode',
    'Direction',
    'TransportProtocol',
    'Intent',
    'AlertStatus',
    'Protocol',
    'Status',
    'StatusReason',
    'SecurityFamily',
    'AadConnectivityState',
    'ExternalSecuritySolutionKind',
    'ControlType',
    'ProvisioningState',
    'HybridComputeProvisioningState',
    'AuthenticationProvisioningState',
    'PermissionProperty',
    'VersionKind',
    'MacSignificance',
    'RelationToIpStatus',
    'ManagementState',
    'AuthorizationState',
    'DeviceCriticality',
    'PurdueLevel',
    'ProgrammingState',
    'ScanningFunctionality',
    'DeviceStatus',
    'ScanTriggerType',
    'ScanState',
    'RuleStatus',
    'RuleSeverity',
    'RuleType',
    'ExpandEnum',
    'ConnectionType',
    'ExpandControlsEnum',
]
