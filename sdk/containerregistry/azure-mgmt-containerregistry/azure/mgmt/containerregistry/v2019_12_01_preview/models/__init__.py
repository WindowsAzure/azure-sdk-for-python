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
    from ._models_py3 import ActiveDirectoryObject
    from ._models_py3 import Actor
    from ._models_py3 import AgentPool
    from ._models_py3 import AgentPoolQueueStatus
    from ._models_py3 import AgentPoolUpdateParameters
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
    from ._models_py3 import EncryptionProperty
    from ._models_py3 import ErrorResponse, ErrorResponseException
    from ._models_py3 import ErrorResponseBody
    from ._models_py3 import Event
    from ._models_py3 import EventContent
    from ._models_py3 import EventInfo
    from ._models_py3 import EventRequestMessage
    from ._models_py3 import EventResponseMessage
    from ._models_py3 import FileTaskRunRequest
    from ._models_py3 import FileTaskStep
    from ._models_py3 import FileTaskStepUpdateParameters
    from ._models_py3 import GenerateCredentialsParameters
    from ._models_py3 import GenerateCredentialsResult
    from ._models_py3 import IdentityProperties
    from ._models_py3 import ImageDescriptor
    from ._models_py3 import ImageUpdateTrigger
    from ._models_py3 import ImportImageParameters
    from ._models_py3 import ImportSource
    from ._models_py3 import ImportSourceCredentials
    from ._models_py3 import IPRule
    from ._models_py3 import KeyVaultProperties
    from ._models_py3 import NetworkRuleSet
    from ._models_py3 import OperationDefinition
    from ._models_py3 import OperationDisplayDefinition
    from ._models_py3 import OperationMetricSpecificationDefinition
    from ._models_py3 import OperationServiceSpecificationDefinition
    from ._models_py3 import OverrideTaskStepProperties
    from ._models_py3 import PlatformProperties
    from ._models_py3 import PlatformUpdateParameters
    from ._models_py3 import Policies
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import ProxyResource
    from ._models_py3 import QuarantinePolicy
    from ._models_py3 import RegenerateCredentialParameters
    from ._models_py3 import Registry
    from ._models_py3 import RegistryListCredentialsResult
    from ._models_py3 import RegistryNameCheckRequest
    from ._models_py3 import RegistryNameStatus
    from ._models_py3 import RegistryPassword
    from ._models_py3 import RegistryUpdateParameters
    from ._models_py3 import RegistryUsage
    from ._models_py3 import RegistryUsageListResult
    from ._models_py3 import Replication
    from ._models_py3 import ReplicationUpdateParameters
    from ._models_py3 import Request
    from ._models_py3 import Resource
    from ._models_py3 import RetentionPolicy
    from ._models_py3 import Run
    from ._models_py3 import RunFilter
    from ._models_py3 import RunGetLogResult
    from ._models_py3 import RunRequest
    from ._models_py3 import RunUpdateParameters
    from ._models_py3 import ScopeMap
    from ._models_py3 import ScopeMapUpdateParameters
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
    from ._models_py3 import TaskRun
    from ._models_py3 import TaskRunRequest
    from ._models_py3 import TaskRunUpdateParameters
    from ._models_py3 import TaskStepProperties
    from ._models_py3 import TaskStepUpdateParameters
    from ._models_py3 import TaskUpdateParameters
    from ._models_py3 import TimerTrigger
    from ._models_py3 import TimerTriggerDescriptor
    from ._models_py3 import TimerTriggerUpdateParameters
    from ._models_py3 import Token
    from ._models_py3 import TokenCertificate
    from ._models_py3 import TokenCredentialsProperties
    from ._models_py3 import TokenPassword
    from ._models_py3 import TokenUpdateParameters
    from ._models_py3 import TriggerProperties
    from ._models_py3 import TriggerUpdateParameters
    from ._models_py3 import TrustPolicy
    from ._models_py3 import UserIdentityProperties
    from ._models_py3 import VirtualNetworkRule
    from ._models_py3 import Webhook
    from ._models_py3 import WebhookCreateParameters
    from ._models_py3 import WebhookUpdateParameters
except (SyntaxError, ImportError):
    from ._models import ActiveDirectoryObject
    from ._models import Actor
    from ._models import AgentPool
    from ._models import AgentPoolQueueStatus
    from ._models import AgentPoolUpdateParameters
    from ._models import AgentProperties
    from ._models import Argument
    from ._models import AuthInfo
    from ._models import AuthInfoUpdateParameters
    from ._models import BaseImageDependency
    from ._models import BaseImageTrigger
    from ._models import BaseImageTriggerUpdateParameters
    from ._models import CallbackConfig
    from ._models import Credentials
    from ._models import CustomRegistryCredentials
    from ._models import DockerBuildRequest
    from ._models import DockerBuildStep
    from ._models import DockerBuildStepUpdateParameters
    from ._models import EncodedTaskRunRequest
    from ._models import EncodedTaskStep
    from ._models import EncodedTaskStepUpdateParameters
    from ._models import EncryptionProperty
    from ._models import ErrorResponse, ErrorResponseException
    from ._models import ErrorResponseBody
    from ._models import Event
    from ._models import EventContent
    from ._models import EventInfo
    from ._models import EventRequestMessage
    from ._models import EventResponseMessage
    from ._models import FileTaskRunRequest
    from ._models import FileTaskStep
    from ._models import FileTaskStepUpdateParameters
    from ._models import GenerateCredentialsParameters
    from ._models import GenerateCredentialsResult
    from ._models import IdentityProperties
    from ._models import ImageDescriptor
    from ._models import ImageUpdateTrigger
    from ._models import ImportImageParameters
    from ._models import ImportSource
    from ._models import ImportSourceCredentials
    from ._models import IPRule
    from ._models import KeyVaultProperties
    from ._models import NetworkRuleSet
    from ._models import OperationDefinition
    from ._models import OperationDisplayDefinition
    from ._models import OperationMetricSpecificationDefinition
    from ._models import OperationServiceSpecificationDefinition
    from ._models import OverrideTaskStepProperties
    from ._models import PlatformProperties
    from ._models import PlatformUpdateParameters
    from ._models import Policies
    from ._models import PrivateEndpoint
    from ._models import PrivateEndpointConnection
    from ._models import PrivateLinkResource
    from ._models import PrivateLinkServiceConnectionState
    from ._models import ProxyResource
    from ._models import QuarantinePolicy
    from ._models import RegenerateCredentialParameters
    from ._models import Registry
    from ._models import RegistryListCredentialsResult
    from ._models import RegistryNameCheckRequest
    from ._models import RegistryNameStatus
    from ._models import RegistryPassword
    from ._models import RegistryUpdateParameters
    from ._models import RegistryUsage
    from ._models import RegistryUsageListResult
    from ._models import Replication
    from ._models import ReplicationUpdateParameters
    from ._models import Request
    from ._models import Resource
    from ._models import RetentionPolicy
    from ._models import Run
    from ._models import RunFilter
    from ._models import RunGetLogResult
    from ._models import RunRequest
    from ._models import RunUpdateParameters
    from ._models import ScopeMap
    from ._models import ScopeMapUpdateParameters
    from ._models import SecretObject
    from ._models import SetValue
    from ._models import Sku
    from ._models import Source
    from ._models import SourceProperties
    from ._models import SourceRegistryCredentials
    from ._models import SourceTrigger
    from ._models import SourceTriggerDescriptor
    from ._models import SourceTriggerUpdateParameters
    from ._models import SourceUpdateParameters
    from ._models import SourceUploadDefinition
    from ._models import Status
    from ._models import StorageAccountProperties
    from ._models import Target
    from ._models import Task
    from ._models import TaskRun
    from ._models import TaskRunRequest
    from ._models import TaskRunUpdateParameters
    from ._models import TaskStepProperties
    from ._models import TaskStepUpdateParameters
    from ._models import TaskUpdateParameters
    from ._models import TimerTrigger
    from ._models import TimerTriggerDescriptor
    from ._models import TimerTriggerUpdateParameters
    from ._models import Token
    from ._models import TokenCertificate
    from ._models import TokenCredentialsProperties
    from ._models import TokenPassword
    from ._models import TokenUpdateParameters
    from ._models import TriggerProperties
    from ._models import TriggerUpdateParameters
    from ._models import TrustPolicy
    from ._models import UserIdentityProperties
    from ._models import VirtualNetworkRule
    from ._models import Webhook
    from ._models import WebhookCreateParameters
    from ._models import WebhookUpdateParameters
from ._paged_models import AgentPoolPaged
from ._paged_models import EventPaged
from ._paged_models import OperationDefinitionPaged
from ._paged_models import PrivateEndpointConnectionPaged
from ._paged_models import PrivateLinkResourcePaged
from ._paged_models import RegistryPaged
from ._paged_models import ReplicationPaged
from ._paged_models import RunPaged
from ._paged_models import ScopeMapPaged
from ._paged_models import TaskPaged
from ._paged_models import TaskRunPaged
from ._paged_models import TokenPaged
from ._paged_models import WebhookPaged
from ._container_registry_management_client_enums import (
    ImportMode,
    ConnectionStatus,
    ActionsRequired,
    ProvisioningState,
    SkuName,
    SkuTier,
    ResourceIdentityType,
    DefaultAction,
    Action,
    PolicyStatus,
    TrustPolicyType,
    EncryptionStatus,
    PasswordName,
    RegistryUsageUnit,
    WebhookStatus,
    WebhookAction,
    OS,
    RunStatus,
    RunType,
    Architecture,
    Variant,
    TaskStatus,
    BaseImageDependencyType,
    TriggerStatus,
    SourceControlType,
    TokenType,
    SourceTriggerEvent,
    BaseImageTriggerType,
    UpdateTriggerPayloadType,
    SourceRegistryLoginMode,
    SecretObjectType,
    TokenCertificateName,
    TokenPasswordName,
    TokenStatus,
)

__all__ = [
    'ActiveDirectoryObject',
    'Actor',
    'AgentPool',
    'AgentPoolQueueStatus',
    'AgentPoolUpdateParameters',
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
    'EncryptionProperty',
    'ErrorResponse', 'ErrorResponseException',
    'ErrorResponseBody',
    'Event',
    'EventContent',
    'EventInfo',
    'EventRequestMessage',
    'EventResponseMessage',
    'FileTaskRunRequest',
    'FileTaskStep',
    'FileTaskStepUpdateParameters',
    'GenerateCredentialsParameters',
    'GenerateCredentialsResult',
    'IdentityProperties',
    'ImageDescriptor',
    'ImageUpdateTrigger',
    'ImportImageParameters',
    'ImportSource',
    'ImportSourceCredentials',
    'IPRule',
    'KeyVaultProperties',
    'NetworkRuleSet',
    'OperationDefinition',
    'OperationDisplayDefinition',
    'OperationMetricSpecificationDefinition',
    'OperationServiceSpecificationDefinition',
    'OverrideTaskStepProperties',
    'PlatformProperties',
    'PlatformUpdateParameters',
    'Policies',
    'PrivateEndpoint',
    'PrivateEndpointConnection',
    'PrivateLinkResource',
    'PrivateLinkServiceConnectionState',
    'ProxyResource',
    'QuarantinePolicy',
    'RegenerateCredentialParameters',
    'Registry',
    'RegistryListCredentialsResult',
    'RegistryNameCheckRequest',
    'RegistryNameStatus',
    'RegistryPassword',
    'RegistryUpdateParameters',
    'RegistryUsage',
    'RegistryUsageListResult',
    'Replication',
    'ReplicationUpdateParameters',
    'Request',
    'Resource',
    'RetentionPolicy',
    'Run',
    'RunFilter',
    'RunGetLogResult',
    'RunRequest',
    'RunUpdateParameters',
    'ScopeMap',
    'ScopeMapUpdateParameters',
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
    'TaskRun',
    'TaskRunRequest',
    'TaskRunUpdateParameters',
    'TaskStepProperties',
    'TaskStepUpdateParameters',
    'TaskUpdateParameters',
    'TimerTrigger',
    'TimerTriggerDescriptor',
    'TimerTriggerUpdateParameters',
    'Token',
    'TokenCertificate',
    'TokenCredentialsProperties',
    'TokenPassword',
    'TokenUpdateParameters',
    'TriggerProperties',
    'TriggerUpdateParameters',
    'TrustPolicy',
    'UserIdentityProperties',
    'VirtualNetworkRule',
    'Webhook',
    'WebhookCreateParameters',
    'WebhookUpdateParameters',
    'RegistryPaged',
    'PrivateLinkResourcePaged',
    'OperationDefinitionPaged',
    'PrivateEndpointConnectionPaged',
    'ReplicationPaged',
    'WebhookPaged',
    'EventPaged',
    'AgentPoolPaged',
    'RunPaged',
    'TaskRunPaged',
    'TaskPaged',
    'ScopeMapPaged',
    'TokenPaged',
    'ImportMode',
    'ConnectionStatus',
    'ActionsRequired',
    'ProvisioningState',
    'SkuName',
    'SkuTier',
    'ResourceIdentityType',
    'DefaultAction',
    'Action',
    'PolicyStatus',
    'TrustPolicyType',
    'EncryptionStatus',
    'PasswordName',
    'RegistryUsageUnit',
    'WebhookStatus',
    'WebhookAction',
    'OS',
    'RunStatus',
    'RunType',
    'Architecture',
    'Variant',
    'TaskStatus',
    'BaseImageDependencyType',
    'TriggerStatus',
    'SourceControlType',
    'TokenType',
    'SourceTriggerEvent',
    'BaseImageTriggerType',
    'UpdateTriggerPayloadType',
    'SourceRegistryLoginMode',
    'SecretObjectType',
    'TokenCertificateName',
    'TokenPasswordName',
    'TokenStatus',
]
