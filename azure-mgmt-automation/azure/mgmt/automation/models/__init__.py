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
    from .sku_py3 import Sku
    from .automation_account_py3 import AutomationAccount
    from .automation_account_create_or_update_parameters_py3 import AutomationAccountCreateOrUpdateParameters
    from .operation_display_py3 import OperationDisplay
    from .operation_py3 import Operation
    from .statistics_py3 import Statistics
    from .usage_counter_name_py3 import UsageCounterName
    from .usage_py3 import Usage
    from .key_py3 import Key
    from .key_list_result_py3 import KeyListResult
    from .automation_account_update_parameters_py3 import AutomationAccountUpdateParameters
    from .proxy_resource_py3 import ProxyResource
    from .resource_py3 import Resource
    from .tracked_resource_py3 import TrackedResource
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .certificate_create_or_update_parameters_py3 import CertificateCreateOrUpdateParameters
    from .certificate_py3 import Certificate
    from .certificate_update_parameters_py3 import CertificateUpdateParameters
    from .connection_type_association_property_py3 import ConnectionTypeAssociationProperty
    from .connection_create_or_update_parameters_py3 import ConnectionCreateOrUpdateParameters
    from .connection_py3 import Connection
    from .connection_update_parameters_py3 import ConnectionUpdateParameters
    from .field_definition_py3 import FieldDefinition
    from .connection_type_py3 import ConnectionType
    from .connection_type_create_or_update_parameters_py3 import ConnectionTypeCreateOrUpdateParameters
    from .credential_create_or_update_parameters_py3 import CredentialCreateOrUpdateParameters
    from .credential_py3 import Credential
    from .credential_update_parameters_py3 import CredentialUpdateParameters
    from .content_hash_py3 import ContentHash
    from .content_source_py3 import ContentSource
    from .dsc_configuration_parameter_py3 import DscConfigurationParameter
    from .dsc_configuration_create_or_update_parameters_py3 import DscConfigurationCreateOrUpdateParameters
    from .dsc_configuration_py3 import DscConfiguration
    from .dsc_configuration_update_parameters_py3 import DscConfigurationUpdateParameters
    from .run_as_credential_association_property_py3 import RunAsCredentialAssociationProperty
    from .hybrid_runbook_worker_py3 import HybridRunbookWorker
    from .hybrid_runbook_worker_group_py3 import HybridRunbookWorkerGroup
    from .hybrid_runbook_worker_group_update_parameters_py3 import HybridRunbookWorkerGroupUpdateParameters
    from .schedule_association_property_py3 import ScheduleAssociationProperty
    from .runbook_association_property_py3 import RunbookAssociationProperty
    from .job_schedule_py3 import JobSchedule
    from .job_schedule_create_parameters_py3 import JobScheduleCreateParameters
    from .linked_workspace_py3 import LinkedWorkspace
    from .activity_parameter_validation_set_py3 import ActivityParameterValidationSet
    from .activity_parameter_py3 import ActivityParameter
    from .activity_parameter_set_py3 import ActivityParameterSet
    from .activity_output_type_py3 import ActivityOutputType
    from .activity_py3 import Activity
    from .module_error_info_py3 import ModuleErrorInfo
    from .content_link_py3 import ContentLink
    from .module_py3 import Module
    from .module_create_or_update_parameters_py3 import ModuleCreateOrUpdateParameters
    from .module_update_parameters_py3 import ModuleUpdateParameters
    from .type_field_py3 import TypeField
    from .runbook_parameter_py3 import RunbookParameter
    from .runbook_draft_py3 import RunbookDraft
    from .runbook_py3 import Runbook
    from .runbook_create_or_update_parameters_py3 import RunbookCreateOrUpdateParameters
    from .runbook_update_parameters_py3 import RunbookUpdateParameters
    from .runbook_draft_undo_edit_result_py3 import RunbookDraftUndoEditResult
    from .test_job_create_parameters_py3 import TestJobCreateParameters
    from .test_job_py3 import TestJob
    from .runbook_create_or_update_draft_properties_py3 import RunbookCreateOrUpdateDraftProperties
    from .runbook_create_or_update_draft_parameters_py3 import RunbookCreateOrUpdateDraftParameters
    from .job_stream_py3 import JobStream
    from .job_stream_list_result_py3 import JobStreamListResult
    from .advanced_schedule_monthly_occurrence_py3 import AdvancedScheduleMonthlyOccurrence
    from .advanced_schedule_py3 import AdvancedSchedule
    from .schedule_create_or_update_parameters_py3 import ScheduleCreateOrUpdateParameters
    from .schedule_properties_py3 import ScheduleProperties
    from .schedule_py3 import Schedule
    from .schedule_update_parameters_py3 import ScheduleUpdateParameters
    from .variable_create_or_update_parameters_py3 import VariableCreateOrUpdateParameters
    from .variable_py3 import Variable
    from .variable_update_parameters_py3 import VariableUpdateParameters
    from .webhook_py3 import Webhook
    from .webhook_update_parameters_py3 import WebhookUpdateParameters
    from .webhook_create_or_update_parameters_py3 import WebhookCreateOrUpdateParameters
    from .watcher_py3 import Watcher
    from .watcher_update_parameters_py3 import WatcherUpdateParameters
    from .windows_properties_py3 import WindowsProperties
    from .linux_properties_py3 import LinuxProperties
    from .update_configuration_py3 import UpdateConfiguration
    from .software_update_configuration_py3 import SoftwareUpdateConfiguration
    from .collection_item_update_configuration_py3 import CollectionItemUpdateConfiguration
    from .software_update_configuration_collection_item_py3 import SoftwareUpdateConfigurationCollectionItem
    from .software_update_configuration_list_result_py3 import SoftwareUpdateConfigurationListResult
    from .update_configuration_navigation_py3 import UpdateConfigurationNavigation
    from .software_update_configuration_run_py3 import SoftwareUpdateConfigurationRun
    from .software_update_configuration_run_list_result_py3 import SoftwareUpdateConfigurationRunListResult
    from .job_navigation_py3 import JobNavigation
    from .software_update_configuration_machine_run_py3 import SoftwareUpdateConfigurationMachineRun
    from .software_update_configuration_machine_run_list_result_py3 import SoftwareUpdateConfigurationMachineRunListResult
    from .source_control_py3 import SourceControl
    from .source_control_security_token_properties_py3 import SourceControlSecurityTokenProperties
    from .source_control_update_parameters_py3 import SourceControlUpdateParameters
    from .source_control_create_or_update_parameters_py3 import SourceControlCreateOrUpdateParameters
    from .source_control_sync_job_py3 import SourceControlSyncJob
    from .source_control_sync_job_create_parameters_py3 import SourceControlSyncJobCreateParameters
    from .source_control_sync_job_by_id_py3 import SourceControlSyncJobById
    from .source_control_sync_job_stream_py3 import SourceControlSyncJobStream
    from .source_control_sync_job_stream_by_id_py3 import SourceControlSyncJobStreamById
    from .job_py3 import Job
    from .job_collection_item_py3 import JobCollectionItem
    from .job_create_parameters_py3 import JobCreateParameters
    from .dsc_report_error_py3 import DscReportError
    from .dsc_report_resource_navigation_py3 import DscReportResourceNavigation
    from .dsc_report_resource_py3 import DscReportResource
    from .dsc_meta_configuration_py3 import DscMetaConfiguration
    from .dsc_node_report_py3 import DscNodeReport
    from .agent_registration_keys_py3 import AgentRegistrationKeys
    from .agent_registration_py3 import AgentRegistration
    from .dsc_node_extension_handler_association_property_py3 import DscNodeExtensionHandlerAssociationProperty
    from .dsc_node_py3 import DscNode
    from .agent_registration_regenerate_key_parameter_py3 import AgentRegistrationRegenerateKeyParameter
    from .dsc_node_update_parameters_properties_py3 import DscNodeUpdateParametersProperties
    from .dsc_node_update_parameters_py3 import DscNodeUpdateParameters
    from .dsc_configuration_association_property_py3 import DscConfigurationAssociationProperty
    from .dsc_compilation_job_py3 import DscCompilationJob
    from .dsc_compilation_job_create_parameters_py3 import DscCompilationJobCreateParameters
    from .dsc_node_configuration_py3 import DscNodeConfiguration
    from .dsc_node_configuration_create_or_update_parameters_py3 import DscNodeConfigurationCreateOrUpdateParameters
    from .node_count_properties_py3 import NodeCountProperties
    from .node_count_py3 import NodeCount
    from .node_counts_py3 import NodeCounts
except (SyntaxError, ImportError):
    from .sku import Sku
    from .automation_account import AutomationAccount
    from .automation_account_create_or_update_parameters import AutomationAccountCreateOrUpdateParameters
    from .operation_display import OperationDisplay
    from .operation import Operation
    from .statistics import Statistics
    from .usage_counter_name import UsageCounterName
    from .usage import Usage
    from .key import Key
    from .key_list_result import KeyListResult
    from .automation_account_update_parameters import AutomationAccountUpdateParameters
    from .proxy_resource import ProxyResource
    from .resource import Resource
    from .tracked_resource import TrackedResource
    from .error_response import ErrorResponse, ErrorResponseException
    from .certificate_create_or_update_parameters import CertificateCreateOrUpdateParameters
    from .certificate import Certificate
    from .certificate_update_parameters import CertificateUpdateParameters
    from .connection_type_association_property import ConnectionTypeAssociationProperty
    from .connection_create_or_update_parameters import ConnectionCreateOrUpdateParameters
    from .connection import Connection
    from .connection_update_parameters import ConnectionUpdateParameters
    from .field_definition import FieldDefinition
    from .connection_type import ConnectionType
    from .connection_type_create_or_update_parameters import ConnectionTypeCreateOrUpdateParameters
    from .credential_create_or_update_parameters import CredentialCreateOrUpdateParameters
    from .credential import Credential
    from .credential_update_parameters import CredentialUpdateParameters
    from .content_hash import ContentHash
    from .content_source import ContentSource
    from .dsc_configuration_parameter import DscConfigurationParameter
    from .dsc_configuration_create_or_update_parameters import DscConfigurationCreateOrUpdateParameters
    from .dsc_configuration import DscConfiguration
    from .dsc_configuration_update_parameters import DscConfigurationUpdateParameters
    from .run_as_credential_association_property import RunAsCredentialAssociationProperty
    from .hybrid_runbook_worker import HybridRunbookWorker
    from .hybrid_runbook_worker_group import HybridRunbookWorkerGroup
    from .hybrid_runbook_worker_group_update_parameters import HybridRunbookWorkerGroupUpdateParameters
    from .schedule_association_property import ScheduleAssociationProperty
    from .runbook_association_property import RunbookAssociationProperty
    from .job_schedule import JobSchedule
    from .job_schedule_create_parameters import JobScheduleCreateParameters
    from .linked_workspace import LinkedWorkspace
    from .activity_parameter_validation_set import ActivityParameterValidationSet
    from .activity_parameter import ActivityParameter
    from .activity_parameter_set import ActivityParameterSet
    from .activity_output_type import ActivityOutputType
    from .activity import Activity
    from .module_error_info import ModuleErrorInfo
    from .content_link import ContentLink
    from .module import Module
    from .module_create_or_update_parameters import ModuleCreateOrUpdateParameters
    from .module_update_parameters import ModuleUpdateParameters
    from .type_field import TypeField
    from .runbook_parameter import RunbookParameter
    from .runbook_draft import RunbookDraft
    from .runbook import Runbook
    from .runbook_create_or_update_parameters import RunbookCreateOrUpdateParameters
    from .runbook_update_parameters import RunbookUpdateParameters
    from .runbook_draft_undo_edit_result import RunbookDraftUndoEditResult
    from .test_job_create_parameters import TestJobCreateParameters
    from .test_job import TestJob
    from .runbook_create_or_update_draft_properties import RunbookCreateOrUpdateDraftProperties
    from .runbook_create_or_update_draft_parameters import RunbookCreateOrUpdateDraftParameters
    from .job_stream import JobStream
    from .job_stream_list_result import JobStreamListResult
    from .advanced_schedule_monthly_occurrence import AdvancedScheduleMonthlyOccurrence
    from .advanced_schedule import AdvancedSchedule
    from .schedule_create_or_update_parameters import ScheduleCreateOrUpdateParameters
    from .schedule_properties import ScheduleProperties
    from .schedule import Schedule
    from .schedule_update_parameters import ScheduleUpdateParameters
    from .variable_create_or_update_parameters import VariableCreateOrUpdateParameters
    from .variable import Variable
    from .variable_update_parameters import VariableUpdateParameters
    from .webhook import Webhook
    from .webhook_update_parameters import WebhookUpdateParameters
    from .webhook_create_or_update_parameters import WebhookCreateOrUpdateParameters
    from .watcher import Watcher
    from .watcher_update_parameters import WatcherUpdateParameters
    from .windows_properties import WindowsProperties
    from .linux_properties import LinuxProperties
    from .update_configuration import UpdateConfiguration
    from .software_update_configuration import SoftwareUpdateConfiguration
    from .collection_item_update_configuration import CollectionItemUpdateConfiguration
    from .software_update_configuration_collection_item import SoftwareUpdateConfigurationCollectionItem
    from .software_update_configuration_list_result import SoftwareUpdateConfigurationListResult
    from .update_configuration_navigation import UpdateConfigurationNavigation
    from .software_update_configuration_run import SoftwareUpdateConfigurationRun
    from .software_update_configuration_run_list_result import SoftwareUpdateConfigurationRunListResult
    from .job_navigation import JobNavigation
    from .software_update_configuration_machine_run import SoftwareUpdateConfigurationMachineRun
    from .software_update_configuration_machine_run_list_result import SoftwareUpdateConfigurationMachineRunListResult
    from .source_control import SourceControl
    from .source_control_security_token_properties import SourceControlSecurityTokenProperties
    from .source_control_update_parameters import SourceControlUpdateParameters
    from .source_control_create_or_update_parameters import SourceControlCreateOrUpdateParameters
    from .source_control_sync_job import SourceControlSyncJob
    from .source_control_sync_job_create_parameters import SourceControlSyncJobCreateParameters
    from .source_control_sync_job_by_id import SourceControlSyncJobById
    from .source_control_sync_job_stream import SourceControlSyncJobStream
    from .source_control_sync_job_stream_by_id import SourceControlSyncJobStreamById
    from .job import Job
    from .job_collection_item import JobCollectionItem
    from .job_create_parameters import JobCreateParameters
    from .dsc_report_error import DscReportError
    from .dsc_report_resource_navigation import DscReportResourceNavigation
    from .dsc_report_resource import DscReportResource
    from .dsc_meta_configuration import DscMetaConfiguration
    from .dsc_node_report import DscNodeReport
    from .agent_registration_keys import AgentRegistrationKeys
    from .agent_registration import AgentRegistration
    from .dsc_node_extension_handler_association_property import DscNodeExtensionHandlerAssociationProperty
    from .dsc_node import DscNode
    from .agent_registration_regenerate_key_parameter import AgentRegistrationRegenerateKeyParameter
    from .dsc_node_update_parameters_properties import DscNodeUpdateParametersProperties
    from .dsc_node_update_parameters import DscNodeUpdateParameters
    from .dsc_configuration_association_property import DscConfigurationAssociationProperty
    from .dsc_compilation_job import DscCompilationJob
    from .dsc_compilation_job_create_parameters import DscCompilationJobCreateParameters
    from .dsc_node_configuration import DscNodeConfiguration
    from .dsc_node_configuration_create_or_update_parameters import DscNodeConfigurationCreateOrUpdateParameters
    from .node_count_properties import NodeCountProperties
    from .node_count import NodeCount
    from .node_counts import NodeCounts
from .automation_account_paged import AutomationAccountPaged
from .operation_paged import OperationPaged
from .statistics_paged import StatisticsPaged
from .usage_paged import UsagePaged
from .certificate_paged import CertificatePaged
from .connection_paged import ConnectionPaged
from .connection_type_paged import ConnectionTypePaged
from .credential_paged import CredentialPaged
from .dsc_configuration_paged import DscConfigurationPaged
from .hybrid_runbook_worker_group_paged import HybridRunbookWorkerGroupPaged
from .job_schedule_paged import JobSchedulePaged
from .activity_paged import ActivityPaged
from .module_paged import ModulePaged
from .type_field_paged import TypeFieldPaged
from .runbook_paged import RunbookPaged
from .job_stream_paged import JobStreamPaged
from .schedule_paged import SchedulePaged
from .variable_paged import VariablePaged
from .webhook_paged import WebhookPaged
from .watcher_paged import WatcherPaged
from .source_control_paged import SourceControlPaged
from .source_control_sync_job_paged import SourceControlSyncJobPaged
from .source_control_sync_job_stream_paged import SourceControlSyncJobStreamPaged
from .job_collection_item_paged import JobCollectionItemPaged
from .dsc_node_paged import DscNodePaged
from .dsc_node_report_paged import DscNodeReportPaged
from .dsc_compilation_job_paged import DscCompilationJobPaged
from .dsc_node_configuration_paged import DscNodeConfigurationPaged
from .automation_client_enums import (
    SkuNameEnum,
    AutomationAccountState,
    AutomationKeyName,
    AutomationKeyPermissions,
    ContentSourceType,
    DscConfigurationProvisioningState,
    DscConfigurationState,
    GroupTypeEnum,
    ModuleProvisioningState,
    RunbookTypeEnum,
    RunbookState,
    RunbookProvisioningState,
    HttpStatusCode,
    JobStreamType,
    ScheduleDay,
    ScheduleFrequency,
    OperatingSystemType,
    WindowsUpdateClasses,
    LinuxUpdateClasses,
    SourceType,
    TokenType,
    ProvisioningState,
    StartType,
    StreamType,
    JobStatus,
    JobProvisioningState,
    AgentRegistrationKeyName,
    CountType,
)

__all__ = [
    'Sku',
    'AutomationAccount',
    'AutomationAccountCreateOrUpdateParameters',
    'OperationDisplay',
    'Operation',
    'Statistics',
    'UsageCounterName',
    'Usage',
    'Key',
    'KeyListResult',
    'AutomationAccountUpdateParameters',
    'ProxyResource',
    'Resource',
    'TrackedResource',
    'ErrorResponse', 'ErrorResponseException',
    'CertificateCreateOrUpdateParameters',
    'Certificate',
    'CertificateUpdateParameters',
    'ConnectionTypeAssociationProperty',
    'ConnectionCreateOrUpdateParameters',
    'Connection',
    'ConnectionUpdateParameters',
    'FieldDefinition',
    'ConnectionType',
    'ConnectionTypeCreateOrUpdateParameters',
    'CredentialCreateOrUpdateParameters',
    'Credential',
    'CredentialUpdateParameters',
    'ContentHash',
    'ContentSource',
    'DscConfigurationParameter',
    'DscConfigurationCreateOrUpdateParameters',
    'DscConfiguration',
    'DscConfigurationUpdateParameters',
    'RunAsCredentialAssociationProperty',
    'HybridRunbookWorker',
    'HybridRunbookWorkerGroup',
    'HybridRunbookWorkerGroupUpdateParameters',
    'ScheduleAssociationProperty',
    'RunbookAssociationProperty',
    'JobSchedule',
    'JobScheduleCreateParameters',
    'LinkedWorkspace',
    'ActivityParameterValidationSet',
    'ActivityParameter',
    'ActivityParameterSet',
    'ActivityOutputType',
    'Activity',
    'ModuleErrorInfo',
    'ContentLink',
    'Module',
    'ModuleCreateOrUpdateParameters',
    'ModuleUpdateParameters',
    'TypeField',
    'RunbookParameter',
    'RunbookDraft',
    'Runbook',
    'RunbookCreateOrUpdateParameters',
    'RunbookUpdateParameters',
    'RunbookDraftUndoEditResult',
    'TestJobCreateParameters',
    'TestJob',
    'RunbookCreateOrUpdateDraftProperties',
    'RunbookCreateOrUpdateDraftParameters',
    'JobStream',
    'JobStreamListResult',
    'AdvancedScheduleMonthlyOccurrence',
    'AdvancedSchedule',
    'ScheduleCreateOrUpdateParameters',
    'ScheduleProperties',
    'Schedule',
    'ScheduleUpdateParameters',
    'VariableCreateOrUpdateParameters',
    'Variable',
    'VariableUpdateParameters',
    'Webhook',
    'WebhookUpdateParameters',
    'WebhookCreateOrUpdateParameters',
    'Watcher',
    'WatcherUpdateParameters',
    'WindowsProperties',
    'LinuxProperties',
    'UpdateConfiguration',
    'SoftwareUpdateConfiguration',
    'CollectionItemUpdateConfiguration',
    'SoftwareUpdateConfigurationCollectionItem',
    'SoftwareUpdateConfigurationListResult',
    'UpdateConfigurationNavigation',
    'SoftwareUpdateConfigurationRun',
    'SoftwareUpdateConfigurationRunListResult',
    'JobNavigation',
    'SoftwareUpdateConfigurationMachineRun',
    'SoftwareUpdateConfigurationMachineRunListResult',
    'SourceControl',
    'SourceControlSecurityTokenProperties',
    'SourceControlUpdateParameters',
    'SourceControlCreateOrUpdateParameters',
    'SourceControlSyncJob',
    'SourceControlSyncJobCreateParameters',
    'SourceControlSyncJobById',
    'SourceControlSyncJobStream',
    'SourceControlSyncJobStreamById',
    'Job',
    'JobCollectionItem',
    'JobCreateParameters',
    'DscReportError',
    'DscReportResourceNavigation',
    'DscReportResource',
    'DscMetaConfiguration',
    'DscNodeReport',
    'AgentRegistrationKeys',
    'AgentRegistration',
    'DscNodeExtensionHandlerAssociationProperty',
    'DscNode',
    'AgentRegistrationRegenerateKeyParameter',
    'DscNodeUpdateParametersProperties',
    'DscNodeUpdateParameters',
    'DscConfigurationAssociationProperty',
    'DscCompilationJob',
    'DscCompilationJobCreateParameters',
    'DscNodeConfiguration',
    'DscNodeConfigurationCreateOrUpdateParameters',
    'NodeCountProperties',
    'NodeCount',
    'NodeCounts',
    'AutomationAccountPaged',
    'OperationPaged',
    'StatisticsPaged',
    'UsagePaged',
    'CertificatePaged',
    'ConnectionPaged',
    'ConnectionTypePaged',
    'CredentialPaged',
    'DscConfigurationPaged',
    'HybridRunbookWorkerGroupPaged',
    'JobSchedulePaged',
    'ActivityPaged',
    'ModulePaged',
    'TypeFieldPaged',
    'RunbookPaged',
    'JobStreamPaged',
    'SchedulePaged',
    'VariablePaged',
    'WebhookPaged',
    'WatcherPaged',
    'SourceControlPaged',
    'SourceControlSyncJobPaged',
    'SourceControlSyncJobStreamPaged',
    'JobCollectionItemPaged',
    'DscNodePaged',
    'DscNodeReportPaged',
    'DscCompilationJobPaged',
    'DscNodeConfigurationPaged',
    'SkuNameEnum',
    'AutomationAccountState',
    'AutomationKeyName',
    'AutomationKeyPermissions',
    'ContentSourceType',
    'DscConfigurationProvisioningState',
    'DscConfigurationState',
    'GroupTypeEnum',
    'ModuleProvisioningState',
    'RunbookTypeEnum',
    'RunbookState',
    'RunbookProvisioningState',
    'HttpStatusCode',
    'JobStreamType',
    'ScheduleDay',
    'ScheduleFrequency',
    'OperatingSystemType',
    'WindowsUpdateClasses',
    'LinuxUpdateClasses',
    'SourceType',
    'TokenType',
    'ProvisioningState',
    'StartType',
    'StreamType',
    'JobStatus',
    'JobProvisioningState',
    'AgentRegistrationKeyName',
    'CountType',
]
