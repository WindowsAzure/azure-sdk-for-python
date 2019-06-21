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
    from .localizable_string_py3 import LocalizableString
    from .metric_value_py3 import MetricValue
    from .metric_py3 import Metric
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .resource_py3 import Resource
    from .retention_policy_py3 import RetentionPolicy
    from .metric_settings_py3 import MetricSettings
    from .log_settings_py3 import LogSettings
    from .service_diagnostic_settings_resource_py3 import ServiceDiagnosticSettingsResource
    from .service_diagnostic_settings_resource_patch_py3 import ServiceDiagnosticSettingsResourcePatch
except (SyntaxError, ImportError):
    from .localizable_string import LocalizableString
    from .metric_value import MetricValue
    from .metric import Metric
    from .error_response import ErrorResponse, ErrorResponseException
    from .resource import Resource
    from .retention_policy import RetentionPolicy
    from .metric_settings import MetricSettings
    from .log_settings import LogSettings
    from .service_diagnostic_settings_resource import ServiceDiagnosticSettingsResource
    from .service_diagnostic_settings_resource_patch import ServiceDiagnosticSettingsResourcePatch
from .metric_paged import MetricPaged
from .monitor_client_enums import (
    Unit,
)

__all__ = [
    'LocalizableString',
    'MetricValue',
    'Metric',
    'ErrorResponse', 'ErrorResponseException',
    'Resource',
    'RetentionPolicy',
    'MetricSettings',
    'LogSettings',
    'ServiceDiagnosticSettingsResource',
    'ServiceDiagnosticSettingsResourcePatch',
    'MetricPaged',
    'Unit',
]
