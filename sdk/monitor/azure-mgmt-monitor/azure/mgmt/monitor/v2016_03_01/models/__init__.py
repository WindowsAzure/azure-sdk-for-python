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
    from .incident_py3 import Incident
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .rule_data_source_py3 import RuleDataSource
    from .rule_condition_py3 import RuleCondition
    from .rule_metric_data_source_py3 import RuleMetricDataSource
    from .rule_management_event_claims_data_source_py3 import RuleManagementEventClaimsDataSource
    from .rule_management_event_data_source_py3 import RuleManagementEventDataSource
    from .threshold_rule_condition_py3 import ThresholdRuleCondition
    from .location_threshold_rule_condition_py3 import LocationThresholdRuleCondition
    from .management_event_aggregation_condition_py3 import ManagementEventAggregationCondition
    from .management_event_rule_condition_py3 import ManagementEventRuleCondition
    from .rule_action_py3 import RuleAction
    from .rule_email_action_py3 import RuleEmailAction
    from .rule_webhook_action_py3 import RuleWebhookAction
    from .resource_py3 import Resource
    from .alert_rule_resource_py3 import AlertRuleResource
    from .alert_rule_resource_patch_py3 import AlertRuleResourcePatch
    from .retention_policy_py3 import RetentionPolicy
    from .log_profile_resource_py3 import LogProfileResource
    from .log_profile_resource_patch_py3 import LogProfileResourcePatch
    from .localizable_string_py3 import LocalizableString
    from .metric_availability_py3 import MetricAvailability
    from .metric_definition_py3 import MetricDefinition
except (SyntaxError, ImportError):
    from .incident import Incident
    from .error_response import ErrorResponse, ErrorResponseException
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
    from .resource import Resource
    from .alert_rule_resource import AlertRuleResource
    from .alert_rule_resource_patch import AlertRuleResourcePatch
    from .retention_policy import RetentionPolicy
    from .log_profile_resource import LogProfileResource
    from .log_profile_resource_patch import LogProfileResourcePatch
    from .localizable_string import LocalizableString
    from .metric_availability import MetricAvailability
    from .metric_definition import MetricDefinition
from .incident_paged import IncidentPaged
from .alert_rule_resource_paged import AlertRuleResourcePaged
from .log_profile_resource_paged import LogProfileResourcePaged
from .metric_definition_paged import MetricDefinitionPaged
from .monitor_management_client_enums import (
    ConditionOperator,
    TimeAggregationOperator,
    Unit,
    AggregationType,
)

__all__ = [
    'Incident',
    'ErrorResponse', 'ErrorResponseException',
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
    'Resource',
    'AlertRuleResource',
    'AlertRuleResourcePatch',
    'RetentionPolicy',
    'LogProfileResource',
    'LogProfileResourcePatch',
    'LocalizableString',
    'MetricAvailability',
    'MetricDefinition',
    'IncidentPaged',
    'AlertRuleResourcePaged',
    'LogProfileResourcePaged',
    'MetricDefinitionPaged',
    'ConditionOperator',
    'TimeAggregationOperator',
    'Unit',
    'AggregationType',
]
