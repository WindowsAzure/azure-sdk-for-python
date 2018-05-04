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
    from .tracked_resource_py3 import TrackedResource
    from .resource_py3 import Resource
    from .sku_py3 import Sku
    from .eh_namespace_py3 import EHNamespace
    from .authorization_rule_py3 import AuthorizationRule
    from .access_keys_py3 import AccessKeys
    from .regenerate_access_key_parameters_py3 import RegenerateAccessKeyParameters
    from .destination_py3 import Destination
    from .capture_description_py3 import CaptureDescription
    from .eventhub_py3 import Eventhub
    from .consumer_group_py3 import ConsumerGroup
    from .check_name_availability_parameter_py3 import CheckNameAvailabilityParameter
    from .check_name_availability_result_py3 import CheckNameAvailabilityResult
    from .operation_display_py3 import OperationDisplay
    from .operation_py3 import Operation
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .arm_disaster_recovery_py3 import ArmDisasterRecovery
    from .messaging_regions_properties_py3 import MessagingRegionsProperties
    from .messaging_regions_py3 import MessagingRegions
    from .messaging_plan_py3 import MessagingPlan
except (SyntaxError, ImportError):
    from .tracked_resource import TrackedResource
    from .resource import Resource
    from .sku import Sku
    from .eh_namespace import EHNamespace
    from .authorization_rule import AuthorizationRule
    from .access_keys import AccessKeys
    from .regenerate_access_key_parameters import RegenerateAccessKeyParameters
    from .destination import Destination
    from .capture_description import CaptureDescription
    from .eventhub import Eventhub
    from .consumer_group import ConsumerGroup
    from .check_name_availability_parameter import CheckNameAvailabilityParameter
    from .check_name_availability_result import CheckNameAvailabilityResult
    from .operation_display import OperationDisplay
    from .operation import Operation
    from .error_response import ErrorResponse, ErrorResponseException
    from .arm_disaster_recovery import ArmDisasterRecovery
    from .messaging_regions_properties import MessagingRegionsProperties
    from .messaging_regions import MessagingRegions
    from .messaging_plan import MessagingPlan
from .operation_paged import OperationPaged
from .eh_namespace_paged import EHNamespacePaged
from .authorization_rule_paged import AuthorizationRulePaged
from .arm_disaster_recovery_paged import ArmDisasterRecoveryPaged
from .eventhub_paged import EventhubPaged
from .consumer_group_paged import ConsumerGroupPaged
from .messaging_regions_paged import MessagingRegionsPaged
from .event_hub_management_client_enums import (
    SkuName,
    SkuTier,
    AccessRights,
    KeyType,
    EntityStatus,
    EncodingCaptureDescription,
    UnavailableReason,
    ProvisioningStateDR,
    RoleDisasterRecovery,
)

__all__ = [
    'TrackedResource',
    'Resource',
    'Sku',
    'EHNamespace',
    'AuthorizationRule',
    'AccessKeys',
    'RegenerateAccessKeyParameters',
    'Destination',
    'CaptureDescription',
    'Eventhub',
    'ConsumerGroup',
    'CheckNameAvailabilityParameter',
    'CheckNameAvailabilityResult',
    'OperationDisplay',
    'Operation',
    'ErrorResponse', 'ErrorResponseException',
    'ArmDisasterRecovery',
    'MessagingRegionsProperties',
    'MessagingRegions',
    'MessagingPlan',
    'OperationPaged',
    'EHNamespacePaged',
    'AuthorizationRulePaged',
    'ArmDisasterRecoveryPaged',
    'EventhubPaged',
    'ConsumerGroupPaged',
    'MessagingRegionsPaged',
    'SkuName',
    'SkuTier',
    'AccessRights',
    'KeyType',
    'EntityStatus',
    'EncodingCaptureDescription',
    'UnavailableReason',
    'ProvisioningStateDR',
    'RoleDisasterRecovery',
]
