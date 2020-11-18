# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import Actor
    from ._models_py3 import AgentProperties
    from ._models_py3 import Argument
    from ._models_py3 import AuthInfo
    from ._models_py3 import AuthInfoUpdateParameters
    from ._models_py3 import BaseImageDependency
    from ._models_py3 import BaseImageTrigger
    from ._models_py3 import BaseImageTriggerUpdateParameters
    from ._models_py3 import CallbackConfig
    from ._models_py3 import Credentials
    from ._models_py3 import CustomRegistryCredentials
    from ._models_py3 import DockerBuildRequest
    from ._models_py3 import DockerBuildStep
    from ._models_py3 import DockerBuildStepUpdateParameters
    from ._models_py3 import EncodedTaskRunRequest
    from ._models_py3 import EncodedTaskStep
    from ._models_py3 import EncodedTaskStepUpdateParameters
    from ._models_py3 import Event
    from ._models_py3 import EventContent
    from ._models_py3 import EventInfo
    from ._models_py3 import EventListResult
    from ._models_py3 import EventRequestMessage
    from ._models_py3 import EventResponseMessage
    from ._models_py3 import FileTaskRunRequest
    from ._models_py3 import FileTaskStep
    from ._models_py3 import FileTaskStepUpdateParameters
    from ._models_py3 import IPRule
    from ._models_py3 import IdentityProperties
    from ._models_py3 import ImageDescriptor
    from ._models_py3 import ImageUpdateTrigger
    from ._models_py3 import ImportImageParameters
    from ._models_py3 import ImportSource
    from ._models_py3 import ImportSourceCredentials
    from ._models_py3 import NetworkRuleSet
    from ._models_py3 import OperationDefinition
    from ._models_py3 import OperationDisplayDefinition
    from ._models_py3 import OperationListResult
    from ._models_py3 import OperationMetricSpecificationDefinition
    from ._models_py3 import OperationServiceSpecificationDefinition
    from ._models_py3 import PlatformProperties
    from ._models_py3 import PlatformUpdateParameters
    from ._models_py3 import Policies
    from ._models_py3 import ProxyResource
    from ._models_py3 import QuarantinePolicy
    from ._models_py3 import RegenerateCredentialParameters
    from ._models_py3 import Registry
    from ._models_py3 import RegistryListCredentialsResult
    from ._models_py3 import RegistryListResult
    from ._models_py3 import RegistryNameCheckRequest
    from ._models_py3 import RegistryNameStatus
    from ._models_py3 import RegistryPassword
    from ._models_py3 import RegistryUpdateParameters
    from ._models_py3 import RegistryUsage
    from ._models_py3 import RegistryUsageListResult
    from ._models_py3 import Replication
    from ._models_py3 import ReplicationListResult
    from ._models_py3 import ReplicationUpdateParameters
    from ._models_py3 import Request
    from ._models_py3 import Resource
    from ._models_py3 import RetentionPolicy
    from ._models_py3 import Run
    from ._models_py3 import RunFilter
    from ._models_py3 import RunGetLogResult
    from ._models_py3 import RunListResult
    from ._models_py3 import RunRequest
    from ._models_py3 import RunUpdateParameters
    from ._models_py3 import SecretObject
    from ._models_py3 import SetValue
    from ._models_py3 import Sku
    from ._models_py3 import Source
    from ._models_py3 import SourceProperties
    from ._models_py3 import SourceRegistryCredentials
    from ._models_py3 import SourceTrigger
    from ._models_py3 import SourceTriggerDescriptor
    from ._models_py3 import SourceTriggerUpdateParameters
    from ._models_py3 import SourceUpdateParameters
    from ._models_py3 import SourceUploadDefinition
    from ._models_py3 import Status
    from ._models_py3 import StorageAccountProperties
    from ._models_py3 import Target
    from ._models_py3 import Task
    from ._models_py3 import TaskListResult
    from ._models_py3 import TaskRunRequest
    from ._models_py3 import TaskStepProperties
    from ._models_py3 import TaskStepUpdateParameters
    from ._models_py3 import TaskUpdateParameters
    from ._models_py3 import TimerTrigger
    from ._models_py3 import TimerTriggerDescriptor
    from ._models_py3 import TimerTriggerUpdateParameters
    from ._models_py3 import TriggerProperties
    from ._models_py3 import TriggerUpdateParameters
    from ._models_py3 import TrustPolicy
    from ._models_py3 import UserIdentityProperties
    from ._models_py3 import VirtualNetworkRule
    from ._models_py3 import Webhook
    from ._models_py3 import WebhookCreateParameters
    from ._models_py3 import WebhookListResult
    from ._models_py3 import WebhookUpdateParameters
except (SyntaxError, ImportError):
    from ._models import Actor  # type: ignore
    from ._models import AgentProperties  # type: ignore
    from ._models import Argument  # type: ignore
    from ._models import AuthInfo  # type: ignore
    from ._models import AuthInfoUpdateParameters  # type: ignore
    from ._models import BaseImageDependency  # type: ignore
    from ._models import BaseImageTrigger  # type: ignore
    from ._models import BaseImageTriggerUpdateParameters  # type: ignore
    from ._models import CallbackConfig  # type: ignore
    from ._models import Credentials  # type: ignore
    from ._models import CustomRegistryCredentials  # type: ignore
    from ._models import DockerBuildRequest  # type: ignore
    from ._models import DockerBuildStep  # type: ignore
    from ._models import DockerBuildStepUpdateParameters  # type: ignore
    from ._models import EncodedTaskRunRequest  # type: ignore
    from ._models import EncodedTaskStep  # type: ignore
    from ._models import EncodedTaskStepUpdateParameters  # type: ignore
    from ._models import Event  # type: ignore
    from ._models import EventContent  # type: ignore
    from ._models import EventInfo  # type: ignore
    from ._models import EventListResult  # type: ignore
    from ._models import EventRequestMessage  # type: ignore
    from ._models import EventResponseMessage  # type: ignore
    from ._models import FileTaskRunRequest  # type: ignore
    from ._models import FileTaskStep  # type: ignore
    from ._models import FileTaskStepUpdateParameters  # type: ignore
    from ._models import IPRule  # type: ignore
    from ._models import IdentityProperties  # type: ignore
    from ._models import ImageDescriptor  # type: ignore
    from ._models import ImageUpdateTrigger  # type: ignore
    from ._models import ImportImageParameters  # type: ignore
    from ._models import ImportSource  # type: ignore
    from ._models import ImportSourceCredentials  # type: ignore
    from ._models import NetworkRuleSet  # type: ignore
    from ._models import OperationDefinition  # type: ignore
    from ._models import OperationDisplayDefinition  # type: ignore
    from ._models import OperationListResult  # type: ignore
    from ._models import OperationMetricSpecificationDefinition  # type: ignore
    from ._models import OperationServiceSpecificationDefinition  # type: ignore
    from ._models import PlatformProperties  # type: ignore
    from ._models import PlatformUpdateParameters  # type: ignore
    from ._models import Policies  # type: ignore
    from ._models import ProxyResource  # type: ignore
    from ._models import QuarantinePolicy  # type: ignore
    from ._models import RegenerateCredentialParameters  # type: ignore
    from ._models import Registry  # type: ignore
    from ._models import RegistryListCredentialsResult  # type: ignore
    from ._models import RegistryListResult  # type: ignore
    from ._models import RegistryNameCheckRequest  # type: ignore
    from ._models import RegistryNameStatus  # type: ignore
    from ._models import RegistryPassword  # type: ignore
    from ._models import RegistryUpdateParameters  # type: ignore
    from ._models import RegistryUsage  # type: ignore
    from ._models import RegistryUsageListResult  # type: ignore
    from ._models import Replication  # type: ignore
    from ._models import ReplicationListResult  # type: ignore
    from ._models import ReplicationUpdateParameters  # type: ignore
    from ._models import Request  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import RetentionPolicy  # type: ignore
    from ._models import Run  # type: ignore
    from ._models import RunFilter  # type: ignore
    from ._models import RunGetLogResult  # type: ignore
    from ._models import RunListResult  # type: ignore
    from ._models import RunRequest  # type: ignore
    from ._models import RunUpdateParameters  # type: ignore
    from ._models import SecretObject  # type: ignore
    from ._models import SetValue  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import Source  # type: ignore
    from ._models import SourceProperties  # type: ignore
    from ._models import SourceRegistryCredentials  # type: ignore
    from ._models import SourceTrigger  # type: ignore
    from ._models import SourceTriggerDescriptor  # type: ignore
    from ._models import SourceTriggerUpdateParameters  # type: ignore
    from ._models import SourceUpdateParameters  # type: ignore
    from ._models import SourceUploadDefinition  # type: ignore
    from ._models import Status  # type: ignore
    from ._models import StorageAccountProperties  # type: ignore
    from ._models import Target  # type: ignore
    from ._models import Task  # type: ignore
    from ._models import TaskListResult  # type: ignore
    from ._models import TaskRunRequest  # type: ignore
    from ._models import TaskStepProperties  # type: ignore
    from ._models import TaskStepUpdateParameters  # type: ignore
    from ._models import TaskUpdateParameters  # type: ignore
    from ._models import TimerTrigger  # type: ignore
    from ._models import TimerTriggerDescriptor  # type: ignore
    from ._models import TimerTriggerUpdateParameters  # type: ignore
    from ._models import TriggerProperties  # type: ignore
    from ._models import TriggerUpdateParameters  # type: ignore
    from ._models import TrustPolicy  # type: ignore
    from ._models import UserIdentityProperties  # type: ignore
    from ._models import VirtualNetworkRule  # type: ignore
    from ._models import Webhook  # type: ignore
    from ._models import WebhookCreateParameters  # type: ignore
    from ._models import WebhookListResult  # type: ignore
    from ._models import WebhookUpdateParameters  # type: ignore

from ._container_registry_management_client_enums import (
    Action,
    Architecture,
    BaseImageDependencyType,
    BaseImageTriggerType,
    DefaultAction,
    ImportMode,
    OS,
    PasswordName,
    PolicyStatus,
    ProvisioningState,
    RegistryUsageUnit,
    ResourceIdentityType,
    RunStatus,
    RunType,
    SecretObjectType,
    SkuName,
    SkuTier,
    SourceControlType,
    SourceRegistryLoginMode,
    SourceTriggerEvent,
    StepType,
    TaskStatus,
    TokenType,
    TriggerStatus,
    TrustPolicyType,
    Variant,
    WebhookAction,
    WebhookStatus,
)

__all__ = [
    'Actor',
    'AgentProperties',
    'Argument',
    'AuthInfo',
    'AuthInfoUpdateParameters',
    'BaseImageDependency',
    'BaseImageTrigger',
    'BaseImageTriggerUpdateParameters',
    'CallbackConfig',
    'Credentials',
    'CustomRegistryCredentials',
    'DockerBuildRequest',
    'DockerBuildStep',
    'DockerBuildStepUpdateParameters',
    'EncodedTaskRunRequest',
    'EncodedTaskStep',
    'EncodedTaskStepUpdateParameters',
    'Event',
    'EventContent',
    'EventInfo',
    'EventListResult',
    'EventRequestMessage',
    'EventResponseMessage',
    'FileTaskRunRequest',
    'FileTaskStep',
    'FileTaskStepUpdateParameters',
    'IPRule',
    'IdentityProperties',
    'ImageDescriptor',
    'ImageUpdateTrigger',
    'ImportImageParameters',
    'ImportSource',
    'ImportSourceCredentials',
    'NetworkRuleSet',
    'OperationDefinition',
    'OperationDisplayDefinition',
    'OperationListResult',
    'OperationMetricSpecificationDefinition',
    'OperationServiceSpecificationDefinition',
    'PlatformProperties',
    'PlatformUpdateParameters',
    'Policies',
    'ProxyResource',
    'QuarantinePolicy',
    'RegenerateCredentialParameters',
    'Registry',
    'RegistryListCredentialsResult',
    'RegistryListResult',
    'RegistryNameCheckRequest',
    'RegistryNameStatus',
    'RegistryPassword',
    'RegistryUpdateParameters',
    'RegistryUsage',
    'RegistryUsageListResult',
    'Replication',
    'ReplicationListResult',
    'ReplicationUpdateParameters',
    'Request',
    'Resource',
    'RetentionPolicy',
    'Run',
    'RunFilter',
    'RunGetLogResult',
    'RunListResult',
    'RunRequest',
    'RunUpdateParameters',
    'SecretObject',
    'SetValue',
    'Sku',
    'Source',
    'SourceProperties',
    'SourceRegistryCredentials',
    'SourceTrigger',
    'SourceTriggerDescriptor',
    'SourceTriggerUpdateParameters',
    'SourceUpdateParameters',
    'SourceUploadDefinition',
    'Status',
    'StorageAccountProperties',
    'Target',
    'Task',
    'TaskListResult',
    'TaskRunRequest',
    'TaskStepProperties',
    'TaskStepUpdateParameters',
    'TaskUpdateParameters',
    'TimerTrigger',
    'TimerTriggerDescriptor',
    'TimerTriggerUpdateParameters',
    'TriggerProperties',
    'TriggerUpdateParameters',
    'TrustPolicy',
    'UserIdentityProperties',
    'VirtualNetworkRule',
    'Webhook',
    'WebhookCreateParameters',
    'WebhookListResult',
    'WebhookUpdateParameters',
    'Action',
    'Architecture',
    'BaseImageDependencyType',
    'BaseImageTriggerType',
    'DefaultAction',
    'ImportMode',
    'OS',
    'PasswordName',
    'PolicyStatus',
    'ProvisioningState',
    'RegistryUsageUnit',
    'ResourceIdentityType',
    'RunStatus',
    'RunType',
    'SecretObjectType',
    'SkuName',
    'SkuTier',
    'SourceControlType',
    'SourceRegistryLoginMode',
    'SourceTriggerEvent',
    'StepType',
    'TaskStatus',
    'TokenType',
    'TriggerStatus',
    'TrustPolicyType',
    'Variant',
    'WebhookAction',
    'WebhookStatus',
]
