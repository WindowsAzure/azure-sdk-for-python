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
    from .resource_py3 import Resource
    from .source_py3 import Source
    from .schedule_py3 import Schedule
    from .action_py3 import Action
    from .log_search_rule_resource_py3 import LogSearchRuleResource
    from .log_search_rule_resource_patch_py3 import LogSearchRuleResourcePatch
    from .log_metric_trigger_py3 import LogMetricTrigger
    from .trigger_condition_py3 import TriggerCondition
    from .az_ns_action_group_py3 import AzNsActionGroup
    from .alerting_action_py3 import AlertingAction
    from .dimension_py3 import Dimension
    from .criteria_py3 import Criteria
    from .log_to_metric_action_py3 import LogToMetricAction
    from .error_response_py3 import ErrorResponse, ErrorResponseException
except (SyntaxError, ImportError):
    from .resource import Resource
    from .source import Source
    from .schedule import Schedule
    from .action import Action
    from .log_search_rule_resource import LogSearchRuleResource
    from .log_search_rule_resource_patch import LogSearchRuleResourcePatch
    from .log_metric_trigger import LogMetricTrigger
    from .trigger_condition import TriggerCondition
    from .az_ns_action_group import AzNsActionGroup
    from .alerting_action import AlertingAction
    from .dimension import Dimension
    from .criteria import Criteria
    from .log_to_metric_action import LogToMetricAction
    from .error_response import ErrorResponse, ErrorResponseException
from .log_search_rule_resource_paged import LogSearchRuleResourcePaged
from .monitor_client_enums import (
    Enabled,
    ProvisioningState,
    QueryType,
    ConditionalOperator,
    MetricTriggerType,
    AlertSeverity,
)

__all__ = [
    'Resource',
    'Source',
    'Schedule',
    'Action',
    'LogSearchRuleResource',
    'LogSearchRuleResourcePatch',
    'LogMetricTrigger',
    'TriggerCondition',
    'AzNsActionGroup',
    'AlertingAction',
    'Dimension',
    'Criteria',
    'LogToMetricAction',
    'ErrorResponse', 'ErrorResponseException',
    'LogSearchRuleResourcePaged',
    'Enabled',
    'ProvisioningState',
    'QueryType',
    'ConditionalOperator',
    'MetricTriggerType',
    'AlertSeverity',
]
