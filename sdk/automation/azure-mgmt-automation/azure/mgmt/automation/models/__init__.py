# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import Activity
    from ._models_py3 import ActivityListResult
    from ._models_py3 import ActivityOutputType
    from ._models_py3 import ActivityParameter
    from ._models_py3 import ActivityParameterSet
    from ._models_py3 import ActivityParameterValidationSet
    from ._models_py3 import AdvancedSchedule
    from ._models_py3 import AdvancedScheduleMonthlyOccurrence
    from ._models_py3 import AgentRegistration
    from ._models_py3 import AgentRegistrationKeys
    from ._models_py3 import AgentRegistrationRegenerateKeyParameter
    from ._models_py3 import AutomationAccount
    from ._models_py3 import AutomationAccountCreateOrUpdateParameters
    from ._models_py3 import AutomationAccountListResult
    from ._models_py3 import AutomationAccountUpdateParameters
    from ._models_py3 import AzureQueryProperties
    from ._models_py3 import Certificate
    from ._models_py3 import CertificateCreateOrUpdateParameters
    from ._models_py3 import CertificateListResult
    from ._models_py3 import CertificateUpdateParameters
    from ._models_py3 import Connection
    from ._models_py3 import ConnectionCreateOrUpdateParameters
    from ._models_py3 import ConnectionListResult
    from ._models_py3 import ConnectionType
    from ._models_py3 import ConnectionTypeAssociationProperty
    from ._models_py3 import ConnectionTypeCreateOrUpdateParameters
    from ._models_py3 import ConnectionTypeListResult
    from ._models_py3 import ConnectionUpdateParameters
    from ._models_py3 import ContentHash
    from ._models_py3 import ContentLink
    from ._models_py3 import ContentSource
    from ._models_py3 import Credential
    from ._models_py3 import CredentialCreateOrUpdateParameters
    from ._models_py3 import CredentialListResult
    from ._models_py3 import CredentialUpdateParameters
    from ._models_py3 import DscCompilationJob
    from ._models_py3 import DscCompilationJobCreateParameters
    from ._models_py3 import DscCompilationJobListResult
    from ._models_py3 import DscConfiguration
    from ._models_py3 import DscConfigurationAssociationProperty
    from ._models_py3 import DscConfigurationCreateOrUpdateParameters
    from ._models_py3 import DscConfigurationListResult
    from ._models_py3 import DscConfigurationParameter
    from ._models_py3 import DscConfigurationUpdateParameters
    from ._models_py3 import DscMetaConfiguration
    from ._models_py3 import DscNode
    from ._models_py3 import DscNodeConfiguration
    from ._models_py3 import DscNodeConfigurationCreateOrUpdateParameters
    from ._models_py3 import DscNodeConfigurationListResult
    from ._models_py3 import DscNodeExtensionHandlerAssociationProperty
    from ._models_py3 import DscNodeListResult
    from ._models_py3 import DscNodeReport
    from ._models_py3 import DscNodeReportListResult
    from ._models_py3 import DscNodeUpdateParameters
    from ._models_py3 import DscNodeUpdateParametersProperties
    from ._models_py3 import DscReportError
    from ._models_py3 import DscReportResource
    from ._models_py3 import DscReportResourceNavigation
    from ._models_py3 import ErrorResponse
    from ._models_py3 import FieldDefinition
    from ._models_py3 import HybridRunbookWorker
    from ._models_py3 import HybridRunbookWorkerGroup
    from ._models_py3 import HybridRunbookWorkerGroupUpdateParameters
    from ._models_py3 import HybridRunbookWorkerGroupsListResult
    from ._models_py3 import Job
    from ._models_py3 import JobCollectionItem
    from ._models_py3 import JobCreateParameters
    from ._models_py3 import JobListResultV2
    from ._models_py3 import JobNavigation
    from ._models_py3 import JobSchedule
    from ._models_py3 import JobScheduleCreateParameters
    from ._models_py3 import JobScheduleListResult
    from ._models_py3 import JobStream
    from ._models_py3 import JobStreamListResult
    from ._models_py3 import Key
    from ._models_py3 import KeyListResult
    from ._models_py3 import LinkedWorkspace
    from ._models_py3 import LinuxProperties
    from ._models_py3 import Module
    from ._models_py3 import ModuleCreateOrUpdateParameters
    from ._models_py3 import ModuleErrorInfo
    from ._models_py3 import ModuleListResult
    from ._models_py3 import ModuleUpdateParameters
    from ._models_py3 import NodeCount
    from ._models_py3 import NodeCountProperties
    from ._models_py3 import NodeCounts
    from ._models_py3 import NonAzureQueryProperties
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationListResult
    from ._models_py3 import ProxyResource
    from ._models_py3 import PythonPackageCreateParameters
    from ._models_py3 import PythonPackageUpdateParameters
    from ._models_py3 import Resource
    from ._models_py3 import RunAsCredentialAssociationProperty
    from ._models_py3 import Runbook
    from ._models_py3 import RunbookAssociationProperty
    from ._models_py3 import RunbookCreateOrUpdateDraftParameters
    from ._models_py3 import RunbookCreateOrUpdateDraftProperties
    from ._models_py3 import RunbookCreateOrUpdateParameters
    from ._models_py3 import RunbookDraft
    from ._models_py3 import RunbookDraftUndoEditResult
    from ._models_py3 import RunbookListResult
    from ._models_py3 import RunbookParameter
    from ._models_py3 import RunbookUpdateParameters
    from ._models_py3 import SUCScheduleProperties
    from ._models_py3 import Schedule
    from ._models_py3 import ScheduleAssociationProperty
    from ._models_py3 import ScheduleCreateOrUpdateParameters
    from ._models_py3 import ScheduleListResult
    from ._models_py3 import ScheduleUpdateParameters
    from ._models_py3 import Sku
    from ._models_py3 import SoftwareUpdateConfiguration
    from ._models_py3 import SoftwareUpdateConfigurationCollectionItem
    from ._models_py3 import SoftwareUpdateConfigurationListResult
    from ._models_py3 import SoftwareUpdateConfigurationMachineRun
    from ._models_py3 import SoftwareUpdateConfigurationMachineRunListResult
    from ._models_py3 import SoftwareUpdateConfigurationRun
    from ._models_py3 import SoftwareUpdateConfigurationRunListResult
    from ._models_py3 import SoftwareUpdateConfigurationRunTaskProperties
    from ._models_py3 import SoftwareUpdateConfigurationRunTasks
    from ._models_py3 import SoftwareUpdateConfigurationTasks
    from ._models_py3 import SourceControl
    from ._models_py3 import SourceControlCreateOrUpdateParameters
    from ._models_py3 import SourceControlListResult
    from ._models_py3 import SourceControlSecurityTokenProperties
    from ._models_py3 import SourceControlSyncJob
    from ._models_py3 import SourceControlSyncJobById
    from ._models_py3 import SourceControlSyncJobCreateParameters
    from ._models_py3 import SourceControlSyncJobListResult
    from ._models_py3 import SourceControlSyncJobStream
    from ._models_py3 import SourceControlSyncJobStreamById
    from ._models_py3 import SourceControlSyncJobStreamsListBySyncJob
    from ._models_py3 import SourceControlUpdateParameters
    from ._models_py3 import Statistics
    from ._models_py3 import StatisticsListResult
    from ._models_py3 import TagSettingsProperties
    from ._models_py3 import TargetProperties
    from ._models_py3 import TaskProperties
    from ._models_py3 import TestJob
    from ._models_py3 import TestJobCreateParameters
    from ._models_py3 import TrackedResource
    from ._models_py3 import TypeField
    from ._models_py3 import TypeFieldListResult
    from ._models_py3 import UpdateConfiguration
    from ._models_py3 import UpdateConfigurationNavigation
    from ._models_py3 import Usage
    from ._models_py3 import UsageCounterName
    from ._models_py3 import UsageListResult
    from ._models_py3 import Variable
    from ._models_py3 import VariableCreateOrUpdateParameters
    from ._models_py3 import VariableListResult
    from ._models_py3 import VariableUpdateParameters
    from ._models_py3 import Watcher
    from ._models_py3 import WatcherListResult
    from ._models_py3 import WatcherUpdateParameters
    from ._models_py3 import Webhook
    from ._models_py3 import WebhookCreateOrUpdateParameters
    from ._models_py3 import WebhookListResult
    from ._models_py3 import WebhookUpdateParameters
    from ._models_py3 import WindowsProperties
except (SyntaxError, ImportError):
    from ._models import Activity  # type: ignore
    from ._models import ActivityListResult  # type: ignore
    from ._models import ActivityOutputType  # type: ignore
    from ._models import ActivityParameter  # type: ignore
    from ._models import ActivityParameterSet  # type: ignore
    from ._models import ActivityParameterValidationSet  # type: ignore
    from ._models import AdvancedSchedule  # type: ignore
    from ._models import AdvancedScheduleMonthlyOccurrence  # type: ignore
    from ._models import AgentRegistration  # type: ignore
    from ._models import AgentRegistrationKeys  # type: ignore
    from ._models import AgentRegistrationRegenerateKeyParameter  # type: ignore
    from ._models import AutomationAccount  # type: ignore
    from ._models import AutomationAccountCreateOrUpdateParameters  # type: ignore
    from ._models import AutomationAccountListResult  # type: ignore
    from ._models import AutomationAccountUpdateParameters  # type: ignore
    from ._models import AzureQueryProperties  # type: ignore
    from ._models import Certificate  # type: ignore
    from ._models import CertificateCreateOrUpdateParameters  # type: ignore
    from ._models import CertificateListResult  # type: ignore
    from ._models import CertificateUpdateParameters  # type: ignore
    from ._models import Connection  # type: ignore
    from ._models import ConnectionCreateOrUpdateParameters  # type: ignore
    from ._models import ConnectionListResult  # type: ignore
    from ._models import ConnectionType  # type: ignore
    from ._models import ConnectionTypeAssociationProperty  # type: ignore
    from ._models import ConnectionTypeCreateOrUpdateParameters  # type: ignore
    from ._models import ConnectionTypeListResult  # type: ignore
    from ._models import ConnectionUpdateParameters  # type: ignore
    from ._models import ContentHash  # type: ignore
    from ._models import ContentLink  # type: ignore
    from ._models import ContentSource  # type: ignore
    from ._models import Credential  # type: ignore
    from ._models import CredentialCreateOrUpdateParameters  # type: ignore
    from ._models import CredentialListResult  # type: ignore
    from ._models import CredentialUpdateParameters  # type: ignore
    from ._models import DscCompilationJob  # type: ignore
    from ._models import DscCompilationJobCreateParameters  # type: ignore
    from ._models import DscCompilationJobListResult  # type: ignore
    from ._models import DscConfiguration  # type: ignore
    from ._models import DscConfigurationAssociationProperty  # type: ignore
    from ._models import DscConfigurationCreateOrUpdateParameters  # type: ignore
    from ._models import DscConfigurationListResult  # type: ignore
    from ._models import DscConfigurationParameter  # type: ignore
    from ._models import DscConfigurationUpdateParameters  # type: ignore
    from ._models import DscMetaConfiguration  # type: ignore
    from ._models import DscNode  # type: ignore
    from ._models import DscNodeConfiguration  # type: ignore
    from ._models import DscNodeConfigurationCreateOrUpdateParameters  # type: ignore
    from ._models import DscNodeConfigurationListResult  # type: ignore
    from ._models import DscNodeExtensionHandlerAssociationProperty  # type: ignore
    from ._models import DscNodeListResult  # type: ignore
    from ._models import DscNodeReport  # type: ignore
    from ._models import DscNodeReportListResult  # type: ignore
    from ._models import DscNodeUpdateParameters  # type: ignore
    from ._models import DscNodeUpdateParametersProperties  # type: ignore
    from ._models import DscReportError  # type: ignore
    from ._models import DscReportResource  # type: ignore
    from ._models import DscReportResourceNavigation  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import FieldDefinition  # type: ignore
    from ._models import HybridRunbookWorker  # type: ignore
    from ._models import HybridRunbookWorkerGroup  # type: ignore
    from ._models import HybridRunbookWorkerGroupUpdateParameters  # type: ignore
    from ._models import HybridRunbookWorkerGroupsListResult  # type: ignore
    from ._models import Job  # type: ignore
    from ._models import JobCollectionItem  # type: ignore
    from ._models import JobCreateParameters  # type: ignore
    from ._models import JobListResultV2  # type: ignore
    from ._models import JobNavigation  # type: ignore
    from ._models import JobSchedule  # type: ignore
    from ._models import JobScheduleCreateParameters  # type: ignore
    from ._models import JobScheduleListResult  # type: ignore
    from ._models import JobStream  # type: ignore
    from ._models import JobStreamListResult  # type: ignore
    from ._models import Key  # type: ignore
    from ._models import KeyListResult  # type: ignore
    from ._models import LinkedWorkspace  # type: ignore
    from ._models import LinuxProperties  # type: ignore
    from ._models import Module  # type: ignore
    from ._models import ModuleCreateOrUpdateParameters  # type: ignore
    from ._models import ModuleErrorInfo  # type: ignore
    from ._models import ModuleListResult  # type: ignore
    from ._models import ModuleUpdateParameters  # type: ignore
    from ._models import NodeCount  # type: ignore
    from ._models import NodeCountProperties  # type: ignore
    from ._models import NodeCounts  # type: ignore
    from ._models import NonAzureQueryProperties  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import OperationListResult  # type: ignore
    from ._models import ProxyResource  # type: ignore
    from ._models import PythonPackageCreateParameters  # type: ignore
    from ._models import PythonPackageUpdateParameters  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import RunAsCredentialAssociationProperty  # type: ignore
    from ._models import Runbook  # type: ignore
    from ._models import RunbookAssociationProperty  # type: ignore
    from ._models import RunbookCreateOrUpdateDraftParameters  # type: ignore
    from ._models import RunbookCreateOrUpdateDraftProperties  # type: ignore
    from ._models import RunbookCreateOrUpdateParameters  # type: ignore
    from ._models import RunbookDraft  # type: ignore
    from ._models import RunbookDraftUndoEditResult  # type: ignore
    from ._models import RunbookListResult  # type: ignore
    from ._models import RunbookParameter  # type: ignore
    from ._models import RunbookUpdateParameters  # type: ignore
    from ._models import SUCScheduleProperties  # type: ignore
    from ._models import Schedule  # type: ignore
    from ._models import ScheduleAssociationProperty  # type: ignore
    from ._models import ScheduleCreateOrUpdateParameters  # type: ignore
    from ._models import ScheduleListResult  # type: ignore
    from ._models import ScheduleUpdateParameters  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import SoftwareUpdateConfiguration  # type: ignore
    from ._models import SoftwareUpdateConfigurationCollectionItem  # type: ignore
    from ._models import SoftwareUpdateConfigurationListResult  # type: ignore
    from ._models import SoftwareUpdateConfigurationMachineRun  # type: ignore
    from ._models import SoftwareUpdateConfigurationMachineRunListResult  # type: ignore
    from ._models import SoftwareUpdateConfigurationRun  # type: ignore
    from ._models import SoftwareUpdateConfigurationRunListResult  # type: ignore
    from ._models import SoftwareUpdateConfigurationRunTaskProperties  # type: ignore
    from ._models import SoftwareUpdateConfigurationRunTasks  # type: ignore
    from ._models import SoftwareUpdateConfigurationTasks  # type: ignore
    from ._models import SourceControl  # type: ignore
    from ._models import SourceControlCreateOrUpdateParameters  # type: ignore
    from ._models import SourceControlListResult  # type: ignore
    from ._models import SourceControlSecurityTokenProperties  # type: ignore
    from ._models import SourceControlSyncJob  # type: ignore
    from ._models import SourceControlSyncJobById  # type: ignore
    from ._models import SourceControlSyncJobCreateParameters  # type: ignore
    from ._models import SourceControlSyncJobListResult  # type: ignore
    from ._models import SourceControlSyncJobStream  # type: ignore
    from ._models import SourceControlSyncJobStreamById  # type: ignore
    from ._models import SourceControlSyncJobStreamsListBySyncJob  # type: ignore
    from ._models import SourceControlUpdateParameters  # type: ignore
    from ._models import Statistics  # type: ignore
    from ._models import StatisticsListResult  # type: ignore
    from ._models import TagSettingsProperties  # type: ignore
    from ._models import TargetProperties  # type: ignore
    from ._models import TaskProperties  # type: ignore
    from ._models import TestJob  # type: ignore
    from ._models import TestJobCreateParameters  # type: ignore
    from ._models import TrackedResource  # type: ignore
    from ._models import TypeField  # type: ignore
    from ._models import TypeFieldListResult  # type: ignore
    from ._models import UpdateConfiguration  # type: ignore
    from ._models import UpdateConfigurationNavigation  # type: ignore
    from ._models import Usage  # type: ignore
    from ._models import UsageCounterName  # type: ignore
    from ._models import UsageListResult  # type: ignore
    from ._models import Variable  # type: ignore
    from ._models import VariableCreateOrUpdateParameters  # type: ignore
    from ._models import VariableListResult  # type: ignore
    from ._models import VariableUpdateParameters  # type: ignore
    from ._models import Watcher  # type: ignore
    from ._models import WatcherListResult  # type: ignore
    from ._models import WatcherUpdateParameters  # type: ignore
    from ._models import Webhook  # type: ignore
    from ._models import WebhookCreateOrUpdateParameters  # type: ignore
    from ._models import WebhookListResult  # type: ignore
    from ._models import WebhookUpdateParameters  # type: ignore
    from ._models import WindowsProperties  # type: ignore

from ._automation_client_enums import (
    AgentRegistrationKeyName,
    AutomationAccountState,
    AutomationKeyName,
    AutomationKeyPermissions,
    ContentSourceType,
    CountType,
    DscConfigurationState,
    GroupTypeEnum,
    HttpStatusCode,
    JobProvisioningState,
    JobStatus,
    JobStreamType,
    LinuxUpdateClasses,
    ModuleProvisioningState,
    OperatingSystemType,
    ProvisioningState,
    RunbookState,
    RunbookTypeEnum,
    ScheduleDay,
    ScheduleFrequency,
    SkuNameEnum,
    SourceType,
    StreamType,
    SyncType,
    TagOperators,
    TokenType,
    WindowsUpdateClasses,
)

__all__ = [
    'Activity',
    'ActivityListResult',
    'ActivityOutputType',
    'ActivityParameter',
    'ActivityParameterSet',
    'ActivityParameterValidationSet',
    'AdvancedSchedule',
    'AdvancedScheduleMonthlyOccurrence',
    'AgentRegistration',
    'AgentRegistrationKeys',
    'AgentRegistrationRegenerateKeyParameter',
    'AutomationAccount',
    'AutomationAccountCreateOrUpdateParameters',
    'AutomationAccountListResult',
    'AutomationAccountUpdateParameters',
    'AzureQueryProperties',
    'Certificate',
    'CertificateCreateOrUpdateParameters',
    'CertificateListResult',
    'CertificateUpdateParameters',
    'Connection',
    'ConnectionCreateOrUpdateParameters',
    'ConnectionListResult',
    'ConnectionType',
    'ConnectionTypeAssociationProperty',
    'ConnectionTypeCreateOrUpdateParameters',
    'ConnectionTypeListResult',
    'ConnectionUpdateParameters',
    'ContentHash',
    'ContentLink',
    'ContentSource',
    'Credential',
    'CredentialCreateOrUpdateParameters',
    'CredentialListResult',
    'CredentialUpdateParameters',
    'DscCompilationJob',
    'DscCompilationJobCreateParameters',
    'DscCompilationJobListResult',
    'DscConfiguration',
    'DscConfigurationAssociationProperty',
    'DscConfigurationCreateOrUpdateParameters',
    'DscConfigurationListResult',
    'DscConfigurationParameter',
    'DscConfigurationUpdateParameters',
    'DscMetaConfiguration',
    'DscNode',
    'DscNodeConfiguration',
    'DscNodeConfigurationCreateOrUpdateParameters',
    'DscNodeConfigurationListResult',
    'DscNodeExtensionHandlerAssociationProperty',
    'DscNodeListResult',
    'DscNodeReport',
    'DscNodeReportListResult',
    'DscNodeUpdateParameters',
    'DscNodeUpdateParametersProperties',
    'DscReportError',
    'DscReportResource',
    'DscReportResourceNavigation',
    'ErrorResponse',
    'FieldDefinition',
    'HybridRunbookWorker',
    'HybridRunbookWorkerGroup',
    'HybridRunbookWorkerGroupUpdateParameters',
    'HybridRunbookWorkerGroupsListResult',
    'Job',
    'JobCollectionItem',
    'JobCreateParameters',
    'JobListResultV2',
    'JobNavigation',
    'JobSchedule',
    'JobScheduleCreateParameters',
    'JobScheduleListResult',
    'JobStream',
    'JobStreamListResult',
    'Key',
    'KeyListResult',
    'LinkedWorkspace',
    'LinuxProperties',
    'Module',
    'ModuleCreateOrUpdateParameters',
    'ModuleErrorInfo',
    'ModuleListResult',
    'ModuleUpdateParameters',
    'NodeCount',
    'NodeCountProperties',
    'NodeCounts',
    'NonAzureQueryProperties',
    'Operation',
    'OperationDisplay',
    'OperationListResult',
    'ProxyResource',
    'PythonPackageCreateParameters',
    'PythonPackageUpdateParameters',
    'Resource',
    'RunAsCredentialAssociationProperty',
    'Runbook',
    'RunbookAssociationProperty',
    'RunbookCreateOrUpdateDraftParameters',
    'RunbookCreateOrUpdateDraftProperties',
    'RunbookCreateOrUpdateParameters',
    'RunbookDraft',
    'RunbookDraftUndoEditResult',
    'RunbookListResult',
    'RunbookParameter',
    'RunbookUpdateParameters',
    'SUCScheduleProperties',
    'Schedule',
    'ScheduleAssociationProperty',
    'ScheduleCreateOrUpdateParameters',
    'ScheduleListResult',
    'ScheduleUpdateParameters',
    'Sku',
    'SoftwareUpdateConfiguration',
    'SoftwareUpdateConfigurationCollectionItem',
    'SoftwareUpdateConfigurationListResult',
    'SoftwareUpdateConfigurationMachineRun',
    'SoftwareUpdateConfigurationMachineRunListResult',
    'SoftwareUpdateConfigurationRun',
    'SoftwareUpdateConfigurationRunListResult',
    'SoftwareUpdateConfigurationRunTaskProperties',
    'SoftwareUpdateConfigurationRunTasks',
    'SoftwareUpdateConfigurationTasks',
    'SourceControl',
    'SourceControlCreateOrUpdateParameters',
    'SourceControlListResult',
    'SourceControlSecurityTokenProperties',
    'SourceControlSyncJob',
    'SourceControlSyncJobById',
    'SourceControlSyncJobCreateParameters',
    'SourceControlSyncJobListResult',
    'SourceControlSyncJobStream',
    'SourceControlSyncJobStreamById',
    'SourceControlSyncJobStreamsListBySyncJob',
    'SourceControlUpdateParameters',
    'Statistics',
    'StatisticsListResult',
    'TagSettingsProperties',
    'TargetProperties',
    'TaskProperties',
    'TestJob',
    'TestJobCreateParameters',
    'TrackedResource',
    'TypeField',
    'TypeFieldListResult',
    'UpdateConfiguration',
    'UpdateConfigurationNavigation',
    'Usage',
    'UsageCounterName',
    'UsageListResult',
    'Variable',
    'VariableCreateOrUpdateParameters',
    'VariableListResult',
    'VariableUpdateParameters',
    'Watcher',
    'WatcherListResult',
    'WatcherUpdateParameters',
    'Webhook',
    'WebhookCreateOrUpdateParameters',
    'WebhookListResult',
    'WebhookUpdateParameters',
    'WindowsProperties',
    'AgentRegistrationKeyName',
    'AutomationAccountState',
    'AutomationKeyName',
    'AutomationKeyPermissions',
    'ContentSourceType',
    'CountType',
    'DscConfigurationState',
    'GroupTypeEnum',
    'HttpStatusCode',
    'JobProvisioningState',
    'JobStatus',
    'JobStreamType',
    'LinuxUpdateClasses',
    'ModuleProvisioningState',
    'OperatingSystemType',
    'ProvisioningState',
    'RunbookState',
    'RunbookTypeEnum',
    'ScheduleDay',
    'ScheduleFrequency',
    'SkuNameEnum',
    'SourceType',
    'StreamType',
    'SyncType',
    'TagOperators',
    'TokenType',
    'WindowsUpdateClasses',
]
