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
    from .import_source_credentials_py3 import ImportSourceCredentials
    from .import_source_py3 import ImportSource
    from .import_image_parameters_py3 import ImportImageParameters
    from .registry_name_check_request_py3 import RegistryNameCheckRequest
    from .registry_name_status_py3 import RegistryNameStatus
    from .operation_display_definition_py3 import OperationDisplayDefinition
    from .operation_metric_specification_definition_py3 import OperationMetricSpecificationDefinition
    from .operation_service_specification_definition_py3 import OperationServiceSpecificationDefinition
    from .operation_definition_py3 import OperationDefinition
    from .sku_py3 import Sku
    from .status1_py3 import Status1
    from .storage_account_properties_py3 import StorageAccountProperties
    from .virtual_network_rule_py3 import VirtualNetworkRule
    from .ip_rule_py3 import IPRule
    from .network_rule_set_py3 import NetworkRuleSet
    from .registry_py3 import Registry
    from .registry_update_parameters_py3 import RegistryUpdateParameters
    from .registry_password_py3 import RegistryPassword
    from .registry_list_credentials_result_py3 import RegistryListCredentialsResult
    from .regenerate_credential_parameters_py3 import RegenerateCredentialParameters
    from .registry_usage_py3 import RegistryUsage
    from .registry_usage_list_result_py3 import RegistryUsageListResult
    from .quarantine_policy_py3 import QuarantinePolicy
    from .trust_policy_py3 import TrustPolicy
    from .registry_policies_py3 import RegistryPolicies
    from .replication_py3 import Replication
    from .replication_update_parameters_py3 import ReplicationUpdateParameters
    from .webhook_py3 import Webhook
    from .webhook_create_parameters_py3 import WebhookCreateParameters
    from .webhook_update_parameters_py3 import WebhookUpdateParameters
    from .event_info_py3 import EventInfo
    from .callback_config_py3 import CallbackConfig
    from .target_py3 import Target
    from .request_py3 import Request
    from .actor_py3 import Actor
    from .source_py3 import Source
    from .event_content_py3 import EventContent
    from .event_request_message_py3 import EventRequestMessage
    from .event_response_message_py3 import EventResponseMessage
    from .event_py3 import Event
    from .resource_py3 import Resource
    from .scope_map_py3 import ScopeMap
    from .scope_map_update_parameters_py3 import ScopeMapUpdateParameters
    from .token_certificate_py3 import TokenCertificate
    from .token_password_py3 import TokenPassword
    from .token_credentials_properties_py3 import TokenCredentialsProperties
    from .token_py3 import Token
    from .token_update_parameters_py3 import TokenUpdateParameters
    from .generate_credentials_parameters_py3 import GenerateCredentialsParameters
    from .generate_credentials_result_py3 import GenerateCredentialsResult
    from .proxy_resource_py3 import ProxyResource
except (SyntaxError, ImportError):
    from .import_source_credentials import ImportSourceCredentials
    from .import_source import ImportSource
    from .import_image_parameters import ImportImageParameters
    from .registry_name_check_request import RegistryNameCheckRequest
    from .registry_name_status import RegistryNameStatus
    from .operation_display_definition import OperationDisplayDefinition
    from .operation_metric_specification_definition import OperationMetricSpecificationDefinition
    from .operation_service_specification_definition import OperationServiceSpecificationDefinition
    from .operation_definition import OperationDefinition
    from .sku import Sku
    from .status1 import Status1
    from .storage_account_properties import StorageAccountProperties
    from .virtual_network_rule import VirtualNetworkRule
    from .ip_rule import IPRule
    from .network_rule_set import NetworkRuleSet
    from .registry import Registry
    from .registry_update_parameters import RegistryUpdateParameters
    from .registry_password import RegistryPassword
    from .registry_list_credentials_result import RegistryListCredentialsResult
    from .regenerate_credential_parameters import RegenerateCredentialParameters
    from .registry_usage import RegistryUsage
    from .registry_usage_list_result import RegistryUsageListResult
    from .quarantine_policy import QuarantinePolicy
    from .trust_policy import TrustPolicy
    from .registry_policies import RegistryPolicies
    from .replication import Replication
    from .replication_update_parameters import ReplicationUpdateParameters
    from .webhook import Webhook
    from .webhook_create_parameters import WebhookCreateParameters
    from .webhook_update_parameters import WebhookUpdateParameters
    from .event_info import EventInfo
    from .callback_config import CallbackConfig
    from .target import Target
    from .request import Request
    from .actor import Actor
    from .source import Source
    from .event_content import EventContent
    from .event_request_message import EventRequestMessage
    from .event_response_message import EventResponseMessage
    from .event import Event
    from .resource import Resource
    from .scope_map import ScopeMap
    from .scope_map_update_parameters import ScopeMapUpdateParameters
    from .token_certificate import TokenCertificate
    from .token_password import TokenPassword
    from .token_credentials_properties import TokenCredentialsProperties
    from .token import Token
    from .token_update_parameters import TokenUpdateParameters
    from .generate_credentials_parameters import GenerateCredentialsParameters
    from .generate_credentials_result import GenerateCredentialsResult
    from .proxy_resource import ProxyResource
from .registry_paged import RegistryPaged
from .operation_definition_paged import OperationDefinitionPaged
from .replication_paged import ReplicationPaged
from .webhook_paged import WebhookPaged
from .event_paged import EventPaged
from .scope_map_paged import ScopeMapPaged
from .token_paged import TokenPaged
from .container_registry_management_client_enums import (
    ImportMode,
    SkuName,
    SkuTier,
    ProvisioningState,
    DefaultAction,
    Action,
    PasswordName,
    RegistryUsageUnit,
    PolicyStatus,
    TrustPolicyType,
    WebhookStatus,
    WebhookAction,
    TokenCertificateName,
    TokenPasswordName,
    Status,
)

__all__ = [
    'ImportSourceCredentials',
    'ImportSource',
    'ImportImageParameters',
    'RegistryNameCheckRequest',
    'RegistryNameStatus',
    'OperationDisplayDefinition',
    'OperationMetricSpecificationDefinition',
    'OperationServiceSpecificationDefinition',
    'OperationDefinition',
    'Sku',
    'Status1',
    'StorageAccountProperties',
    'VirtualNetworkRule',
    'IPRule',
    'NetworkRuleSet',
    'Registry',
    'RegistryUpdateParameters',
    'RegistryPassword',
    'RegistryListCredentialsResult',
    'RegenerateCredentialParameters',
    'RegistryUsage',
    'RegistryUsageListResult',
    'QuarantinePolicy',
    'TrustPolicy',
    'RegistryPolicies',
    'Replication',
    'ReplicationUpdateParameters',
    'Webhook',
    'WebhookCreateParameters',
    'WebhookUpdateParameters',
    'EventInfo',
    'CallbackConfig',
    'Target',
    'Request',
    'Actor',
    'Source',
    'EventContent',
    'EventRequestMessage',
    'EventResponseMessage',
    'Event',
    'Resource',
    'ScopeMap',
    'ScopeMapUpdateParameters',
    'TokenCertificate',
    'TokenPassword',
    'TokenCredentialsProperties',
    'Token',
    'TokenUpdateParameters',
    'GenerateCredentialsParameters',
    'GenerateCredentialsResult',
    'ProxyResource',
    'RegistryPaged',
    'OperationDefinitionPaged',
    'ReplicationPaged',
    'WebhookPaged',
    'EventPaged',
    'ScopeMapPaged',
    'TokenPaged',
    'ImportMode',
    'SkuName',
    'SkuTier',
    'ProvisioningState',
    'DefaultAction',
    'Action',
    'PasswordName',
    'RegistryUsageUnit',
    'PolicyStatus',
    'TrustPolicyType',
    'WebhookStatus',
    'WebhookAction',
    'TokenCertificateName',
    'TokenPasswordName',
    'Status',
]
