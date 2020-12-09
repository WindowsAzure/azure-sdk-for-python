# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AddUsersPayload
    from ._models_py3 import CloudErrorBody
    from ._models_py3 import CreateLabProperties
    from ._models_py3 import Environment
    from ._models_py3 import EnvironmentDetails
    from ._models_py3 import EnvironmentFragment
    from ._models_py3 import EnvironmentOperationsPayload
    from ._models_py3 import EnvironmentSetting
    from ._models_py3 import EnvironmentSettingCreationParameters
    from ._models_py3 import EnvironmentSettingFragment
    from ._models_py3 import EnvironmentSize
    from ._models_py3 import EnvironmentSizeFragment
    from ._models_py3 import GalleryImage
    from ._models_py3 import GalleryImageFragment
    from ._models_py3 import GalleryImageReference
    from ._models_py3 import GalleryImageReferenceFragment
    from ._models_py3 import GetEnvironmentResponse
    from ._models_py3 import GetPersonalPreferencesResponse
    from ._models_py3 import GetRegionalAvailabilityResponse
    from ._models_py3 import Lab
    from ._models_py3 import LabAccount
    from ._models_py3 import LabAccountFragment
    from ._models_py3 import LabCreationParameters
    from ._models_py3 import LabDetails
    from ._models_py3 import LabFragment
    from ._models_py3 import LatestOperationResult
    from ._models_py3 import ListEnvironmentsPayload
    from ._models_py3 import ListEnvironmentsResponse
    from ._models_py3 import ListLabsResponse
    from ._models_py3 import NetworkInterface
    from ._models_py3 import OperationBatchStatusPayload
    from ._models_py3 import OperationBatchStatusResponse
    from ._models_py3 import OperationBatchStatusResponseItem
    from ._models_py3 import OperationError
    from ._models_py3 import OperationMetadata
    from ._models_py3 import OperationMetadataDisplay
    from ._models_py3 import OperationResult
    from ._models_py3 import OperationStatusPayload
    from ._models_py3 import OperationStatusResponse
    from ._models_py3 import PersonalPreferencesOperationsPayload
    from ._models_py3 import ProviderOperationResult
    from ._models_py3 import PublishPayload
    from ._models_py3 import ReferenceVm
    from ._models_py3 import ReferenceVmCreationParameters
    from ._models_py3 import ReferenceVmFragment
    from ._models_py3 import RegionalAvailability
    from ._models_py3 import RegisterPayload
    from ._models_py3 import ResetPasswordPayload
    from ._models_py3 import Resource
    from ._models_py3 import ResourceSet
    from ._models_py3 import ResourceSetFragment
    from ._models_py3 import ResourceSettingCreationParameters
    from ._models_py3 import ResourceSettings
    from ._models_py3 import ResourceSettingsFragment
    from ._models_py3 import ResponseWithContinuationEnvironment
    from ._models_py3 import ResponseWithContinuationEnvironmentSetting
    from ._models_py3 import ResponseWithContinuationGalleryImage
    from ._models_py3 import ResponseWithContinuationLab
    from ._models_py3 import ResponseWithContinuationLabAccount
    from ._models_py3 import ResponseWithContinuationUser
    from ._models_py3 import SizeAvailability
    from ._models_py3 import SizeConfigurationProperties
    from ._models_py3 import SizeConfigurationPropertiesFragment
    from ._models_py3 import SizeInfo
    from ._models_py3 import SizeInfoFragment
    from ._models_py3 import User
    from ._models_py3 import UserFragment
    from ._models_py3 import VirtualMachineDetails
    from ._models_py3 import VmStateDetails
except (SyntaxError, ImportError):
    from ._models import AddUsersPayload  # type: ignore
    from ._models import CloudErrorBody  # type: ignore
    from ._models import CreateLabProperties  # type: ignore
    from ._models import Environment  # type: ignore
    from ._models import EnvironmentDetails  # type: ignore
    from ._models import EnvironmentFragment  # type: ignore
    from ._models import EnvironmentOperationsPayload  # type: ignore
    from ._models import EnvironmentSetting  # type: ignore
    from ._models import EnvironmentSettingCreationParameters  # type: ignore
    from ._models import EnvironmentSettingFragment  # type: ignore
    from ._models import EnvironmentSize  # type: ignore
    from ._models import EnvironmentSizeFragment  # type: ignore
    from ._models import GalleryImage  # type: ignore
    from ._models import GalleryImageFragment  # type: ignore
    from ._models import GalleryImageReference  # type: ignore
    from ._models import GalleryImageReferenceFragment  # type: ignore
    from ._models import GetEnvironmentResponse  # type: ignore
    from ._models import GetPersonalPreferencesResponse  # type: ignore
    from ._models import GetRegionalAvailabilityResponse  # type: ignore
    from ._models import Lab  # type: ignore
    from ._models import LabAccount  # type: ignore
    from ._models import LabAccountFragment  # type: ignore
    from ._models import LabCreationParameters  # type: ignore
    from ._models import LabDetails  # type: ignore
    from ._models import LabFragment  # type: ignore
    from ._models import LatestOperationResult  # type: ignore
    from ._models import ListEnvironmentsPayload  # type: ignore
    from ._models import ListEnvironmentsResponse  # type: ignore
    from ._models import ListLabsResponse  # type: ignore
    from ._models import NetworkInterface  # type: ignore
    from ._models import OperationBatchStatusPayload  # type: ignore
    from ._models import OperationBatchStatusResponse  # type: ignore
    from ._models import OperationBatchStatusResponseItem  # type: ignore
    from ._models import OperationError  # type: ignore
    from ._models import OperationMetadata  # type: ignore
    from ._models import OperationMetadataDisplay  # type: ignore
    from ._models import OperationResult  # type: ignore
    from ._models import OperationStatusPayload  # type: ignore
    from ._models import OperationStatusResponse  # type: ignore
    from ._models import PersonalPreferencesOperationsPayload  # type: ignore
    from ._models import ProviderOperationResult  # type: ignore
    from ._models import PublishPayload  # type: ignore
    from ._models import ReferenceVm  # type: ignore
    from ._models import ReferenceVmCreationParameters  # type: ignore
    from ._models import ReferenceVmFragment  # type: ignore
    from ._models import RegionalAvailability  # type: ignore
    from ._models import RegisterPayload  # type: ignore
    from ._models import ResetPasswordPayload  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceSet  # type: ignore
    from ._models import ResourceSetFragment  # type: ignore
    from ._models import ResourceSettingCreationParameters  # type: ignore
    from ._models import ResourceSettings  # type: ignore
    from ._models import ResourceSettingsFragment  # type: ignore
    from ._models import ResponseWithContinuationEnvironment  # type: ignore
    from ._models import ResponseWithContinuationEnvironmentSetting  # type: ignore
    from ._models import ResponseWithContinuationGalleryImage  # type: ignore
    from ._models import ResponseWithContinuationLab  # type: ignore
    from ._models import ResponseWithContinuationLabAccount  # type: ignore
    from ._models import ResponseWithContinuationUser  # type: ignore
    from ._models import SizeAvailability  # type: ignore
    from ._models import SizeConfigurationProperties  # type: ignore
    from ._models import SizeConfigurationPropertiesFragment  # type: ignore
    from ._models import SizeInfo  # type: ignore
    from ._models import SizeInfoFragment  # type: ignore
    from ._models import User  # type: ignore
    from ._models import UserFragment  # type: ignore
    from ._models import VirtualMachineDetails  # type: ignore
    from ._models import VmStateDetails  # type: ignore

from ._managed_labs_client_enums import (
    AddRemove,
    ConfigurationState,
    LabUserAccessMode,
    ManagedLabVmSize,
    PublishingState,
)

__all__ = [
    'AddUsersPayload',
    'CloudErrorBody',
    'CreateLabProperties',
    'Environment',
    'EnvironmentDetails',
    'EnvironmentFragment',
    'EnvironmentOperationsPayload',
    'EnvironmentSetting',
    'EnvironmentSettingCreationParameters',
    'EnvironmentSettingFragment',
    'EnvironmentSize',
    'EnvironmentSizeFragment',
    'GalleryImage',
    'GalleryImageFragment',
    'GalleryImageReference',
    'GalleryImageReferenceFragment',
    'GetEnvironmentResponse',
    'GetPersonalPreferencesResponse',
    'GetRegionalAvailabilityResponse',
    'Lab',
    'LabAccount',
    'LabAccountFragment',
    'LabCreationParameters',
    'LabDetails',
    'LabFragment',
    'LatestOperationResult',
    'ListEnvironmentsPayload',
    'ListEnvironmentsResponse',
    'ListLabsResponse',
    'NetworkInterface',
    'OperationBatchStatusPayload',
    'OperationBatchStatusResponse',
    'OperationBatchStatusResponseItem',
    'OperationError',
    'OperationMetadata',
    'OperationMetadataDisplay',
    'OperationResult',
    'OperationStatusPayload',
    'OperationStatusResponse',
    'PersonalPreferencesOperationsPayload',
    'ProviderOperationResult',
    'PublishPayload',
    'ReferenceVm',
    'ReferenceVmCreationParameters',
    'ReferenceVmFragment',
    'RegionalAvailability',
    'RegisterPayload',
    'ResetPasswordPayload',
    'Resource',
    'ResourceSet',
    'ResourceSetFragment',
    'ResourceSettingCreationParameters',
    'ResourceSettings',
    'ResourceSettingsFragment',
    'ResponseWithContinuationEnvironment',
    'ResponseWithContinuationEnvironmentSetting',
    'ResponseWithContinuationGalleryImage',
    'ResponseWithContinuationLab',
    'ResponseWithContinuationLabAccount',
    'ResponseWithContinuationUser',
    'SizeAvailability',
    'SizeConfigurationProperties',
    'SizeConfigurationPropertiesFragment',
    'SizeInfo',
    'SizeInfoFragment',
    'User',
    'UserFragment',
    'VirtualMachineDetails',
    'VmStateDetails',
    'AddRemove',
    'ConfigurationState',
    'LabUserAccessMode',
    'ManagedLabVmSize',
    'PublishingState',
]
