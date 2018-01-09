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

from .resource import Resource
from .scale_capacity import ScaleCapacity
from .metric_trigger import MetricTrigger
from .scale_action import ScaleAction
from .scale_rule import ScaleRule
from .time_window import TimeWindow
from .recurrent_schedule import RecurrentSchedule
from .recurrence import Recurrence
from .autoscale_profile import AutoscaleProfile
from .email_notification import EmailNotification
from .webhook_notification import WebhookNotification
from .autoscale_notification import AutoscaleNotification
from .autoscale_setting_resource import AutoscaleSettingResource
from .autoscale_setting_resource_patch import AutoscaleSettingResourcePatch
from .error_response import ErrorResponse, ErrorResponseException
from .operation_display import OperationDisplay
from .operation import Operation
from .operation_list_result import OperationListResult
from .incident import Incident
from .rule_data_source import RuleDataSource
from .rule_condition import RuleCondition
from .rule_metric_data_source import RuleMetricDataSource
from .rule_management_event_claims_data_source import RuleManagementEventClaimsDataSource
from .rule_management_event_data_source import RuleManagementEventDataSource
from .threshold_rule_condition import ThresholdRuleCondition
from .location_threshold_rule_condition import LocationThresholdRuleCondition
from .management_event_aggregation_condition import ManagementEventAggregationCondition
from .management_event_rule_condition import ManagementEventRuleCondition
from .rule_action import RuleAction
from .rule_email_action import RuleEmailAction
from .rule_webhook_action import RuleWebhookAction
from .alert_rule_resource import AlertRuleResource
from .alert_rule_resource_patch import AlertRuleResourcePatch
from .retention_policy import RetentionPolicy
from .log_profile_resource import LogProfileResource
from .log_profile_resource_patch import LogProfileResourcePatch
from .proxy_only_resource import ProxyOnlyResource
from .metric_settings import MetricSettings
from .log_settings import LogSettings
from .diagnostic_settings_resource import DiagnosticSettingsResource
from .diagnostic_settings_resource_collection import DiagnosticSettingsResourceCollection
from .diagnostic_settings_category_resource import DiagnosticSettingsCategoryResource
from .diagnostic_settings_category_resource_collection import DiagnosticSettingsCategoryResourceCollection
from .email_receiver import EmailReceiver
from .sms_receiver import SmsReceiver
from .webhook_receiver import WebhookReceiver
from .action_group_resource import ActionGroupResource
from .enable_request import EnableRequest
from .activity_log_alert_leaf_condition import ActivityLogAlertLeafCondition
from .activity_log_alert_all_of_condition import ActivityLogAlertAllOfCondition
from .activity_log_alert_action_group import ActivityLogAlertActionGroup
from .activity_log_alert_action_list import ActivityLogAlertActionList
from .activity_log_alert_resource import ActivityLogAlertResource
from .activity_log_alert_patch_body import ActivityLogAlertPatchBody
from .localizable_string import LocalizableString
from .sender_authorization import SenderAuthorization
from .http_request_info import HttpRequestInfo
from .event_data import EventData
from .metric_availability import MetricAvailability
from .metric_definition import MetricDefinition
from .metric_value import MetricValue
from .metadata_value import MetadataValue
from .time_series_element import TimeSeriesElement
from .metric import Metric
from .response import Response
from .baseline_metadata_value import BaselineMetadataValue
from .baseline import Baseline
from .baseline_response import BaselineResponse
from .time_series_information import TimeSeriesInformation
from .calculate_baseline_response import CalculateBaselineResponse
from .autoscale_setting_resource_paged import AutoscaleSettingResourcePaged
from .incident_paged import IncidentPaged
from .alert_rule_resource_paged import AlertRuleResourcePaged
from .log_profile_resource_paged import LogProfileResourcePaged
from .action_group_resource_paged import ActionGroupResourcePaged
from .activity_log_alert_resource_paged import ActivityLogAlertResourcePaged
from .event_data_paged import EventDataPaged
from .localizable_string_paged import LocalizableStringPaged
from .metric_definition_paged import MetricDefinitionPaged
from .monitor_management_client_enums import (
    MetricStatisticType,
    TimeAggregationType,
    ComparisonOperationType,
    ScaleDirection,
    ScaleType,
    RecurrenceFrequency,
    ConditionOperator,
    TimeAggregationOperator,
    CategoryType,
    ReceiverStatus,
    EventLevel,
    Unit,
    AggregationType,
    Sensitivity,
    ResultType,
)

__all__ = [
    'Resource',
    'ScaleCapacity',
    'MetricTrigger',
    'ScaleAction',
    'ScaleRule',
    'TimeWindow',
    'RecurrentSchedule',
    'Recurrence',
    'AutoscaleProfile',
    'EmailNotification',
    'WebhookNotification',
    'AutoscaleNotification',
    'AutoscaleSettingResource',
    'AutoscaleSettingResourcePatch',
    'ErrorResponse', 'ErrorResponseException',
    'OperationDisplay',
    'Operation',
    'OperationListResult',
    'Incident',
    'RuleDataSource',
    'RuleCondition',
    'RuleMetricDataSource',
    'RuleManagementEventClaimsDataSource',
    'RuleManagementEventDataSource',
    'ThresholdRuleCondition',
    'LocationThresholdRuleCondition',
    'ManagementEventAggregationCondition',
    'ManagementEventRuleCondition',
    'RuleAction',
    'RuleEmailAction',
    'RuleWebhookAction',
    'AlertRuleResource',
    'AlertRuleResourcePatch',
    'RetentionPolicy',
    'LogProfileResource',
    'LogProfileResourcePatch',
    'ProxyOnlyResource',
    'MetricSettings',
    'LogSettings',
    'DiagnosticSettingsResource',
    'DiagnosticSettingsResourceCollection',
    'DiagnosticSettingsCategoryResource',
    'DiagnosticSettingsCategoryResourceCollection',
    'EmailReceiver',
    'SmsReceiver',
    'WebhookReceiver',
    'ActionGroupResource',
    'EnableRequest',
    'ActivityLogAlertLeafCondition',
    'ActivityLogAlertAllOfCondition',
    'ActivityLogAlertActionGroup',
    'ActivityLogAlertActionList',
    'ActivityLogAlertResource',
    'ActivityLogAlertPatchBody',
    'LocalizableString',
    'SenderAuthorization',
    'HttpRequestInfo',
    'EventData',
    'MetricAvailability',
    'MetricDefinition',
    'MetricValue',
    'MetadataValue',
    'TimeSeriesElement',
    'Metric',
    'Response',
    'BaselineMetadataValue',
    'Baseline',
    'BaselineResponse',
    'TimeSeriesInformation',
    'CalculateBaselineResponse',
    'AutoscaleSettingResourcePaged',
    'IncidentPaged',
    'AlertRuleResourcePaged',
    'LogProfileResourcePaged',
    'ActionGroupResourcePaged',
    'ActivityLogAlertResourcePaged',
    'EventDataPaged',
    'LocalizableStringPaged',
    'MetricDefinitionPaged',
    'MetricStatisticType',
    'TimeAggregationType',
    'ComparisonOperationType',
    'ScaleDirection',
    'ScaleType',
    'RecurrenceFrequency',
    'ConditionOperator',
    'TimeAggregationOperator',
    'CategoryType',
    'ReceiverStatus',
    'EventLevel',
    'Unit',
    'AggregationType',
    'Sensitivity',
    'ResultType',
]
