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
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .guest_diagnostic_settings_association_resource_py3 import GuestDiagnosticSettingsAssociationResource
    from .guest_diagnostic_settings_association_resource_patch_py3 import GuestDiagnosticSettingsAssociationResourcePatch
    from .resource_py3 import Resource
    from .etw_event_configuration_py3 import EtwEventConfiguration
    from .etw_provider_configuration_py3 import EtwProviderConfiguration
    from .performance_counter_configuration_py3 import PerformanceCounterConfiguration
    from .event_log_configuration_py3 import EventLogConfiguration
    from .data_source_configuration_py3 import DataSourceConfiguration
    from .sink_configuration_py3 import SinkConfiguration
    from .data_source_py3 import DataSource
    from .guest_diagnostic_settings_resource_py3 import GuestDiagnosticSettingsResource
    from .guest_diagnostic_settings_patch_resource_py3 import GuestDiagnosticSettingsPatchResource
except (SyntaxError, ImportError):
    from .error_response import ErrorResponse, ErrorResponseException
    from .guest_diagnostic_settings_association_resource import GuestDiagnosticSettingsAssociationResource
    from .guest_diagnostic_settings_association_resource_patch import GuestDiagnosticSettingsAssociationResourcePatch
    from .resource import Resource
    from .etw_event_configuration import EtwEventConfiguration
    from .etw_provider_configuration import EtwProviderConfiguration
    from .performance_counter_configuration import PerformanceCounterConfiguration
    from .event_log_configuration import EventLogConfiguration
    from .data_source_configuration import DataSourceConfiguration
    from .sink_configuration import SinkConfiguration
    from .data_source import DataSource
    from .guest_diagnostic_settings_resource import GuestDiagnosticSettingsResource
    from .guest_diagnostic_settings_patch_resource import GuestDiagnosticSettingsPatchResource
from .guest_diagnostic_settings_association_resource_paged import GuestDiagnosticSettingsAssociationResourcePaged
from .guest_diagnostic_settings_resource_paged import GuestDiagnosticSettingsResourcePaged

__all__ = [
    'ErrorResponse', 'ErrorResponseException',
    'GuestDiagnosticSettingsAssociationResource',
    'GuestDiagnosticSettingsAssociationResourcePatch',
    'Resource',
    'EtwEventConfiguration',
    'EtwProviderConfiguration',
    'PerformanceCounterConfiguration',
    'EventLogConfiguration',
    'DataSourceConfiguration',
    'SinkConfiguration',
    'DataSource',
    'GuestDiagnosticSettingsResource',
    'GuestDiagnosticSettingsPatchResource',
    'GuestDiagnosticSettingsAssociationResourcePaged',
    'GuestDiagnosticSettingsResourcePaged',
]
