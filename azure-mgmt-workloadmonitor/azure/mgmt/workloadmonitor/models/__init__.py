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
    from .monitor_criteria_py3 import MonitorCriteria
    from .monitor_py3 import Monitor
    from .component_py3 import Component
    from .health_state_change_py3 import HealthStateChange
    from .monitor_instance_py3 import MonitorInstance
    from .notification_setting_py3 import NotificationSetting
    from .operation_properties_py3 import OperationProperties
    from .operation_py3 import Operation
    from .error_field_contract_py3 import ErrorFieldContract
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .tracked_resource_py3 import TrackedResource
    from .azure_entity_resource_py3 import AzureEntityResource
    from .resource_py3 import Resource
    from .proxy_resource_py3 import ProxyResource
except (SyntaxError, ImportError):
    from .monitor_criteria import MonitorCriteria
    from .monitor import Monitor
    from .component import Component
    from .health_state_change import HealthStateChange
    from .monitor_instance import MonitorInstance
    from .notification_setting import NotificationSetting
    from .operation_properties import OperationProperties
    from .operation import Operation
    from .error_field_contract import ErrorFieldContract
    from .error_response import ErrorResponse, ErrorResponseException
    from .tracked_resource import TrackedResource
    from .azure_entity_resource import AzureEntityResource
    from .resource import Resource
    from .proxy_resource import ProxyResource
from .monitor_paged import MonitorPaged
from .component_paged import ComponentPaged
from .monitor_instance_paged import MonitorInstancePaged
from .notification_setting_paged import NotificationSettingPaged
from .operation_paged import OperationPaged
from .workload_monitor_api_enums import (
    MonitorType,
    MonitorCategory,
    MonitorState,
    HealthState,
    Operator,
    AlertGeneration,
    WorkloadType,
    HealthStateCategory,
)

__all__ = [
    'MonitorCriteria',
    'Monitor',
    'Component',
    'HealthStateChange',
    'MonitorInstance',
    'NotificationSetting',
    'OperationProperties',
    'Operation',
    'ErrorFieldContract',
    'ErrorResponse', 'ErrorResponseException',
    'TrackedResource',
    'AzureEntityResource',
    'Resource',
    'ProxyResource',
    'MonitorPaged',
    'ComponentPaged',
    'MonitorInstancePaged',
    'NotificationSettingPaged',
    'OperationPaged',
    'MonitorType',
    'MonitorCategory',
    'MonitorState',
    'HealthState',
    'Operator',
    'AlertGeneration',
    'WorkloadType',
    'HealthStateCategory',
]
