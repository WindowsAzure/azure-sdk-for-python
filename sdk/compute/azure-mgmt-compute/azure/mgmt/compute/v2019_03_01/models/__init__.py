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
    from ._models_py3 import AccessUri
    from ._models_py3 import AdditionalCapabilities
    from ._models_py3 import AdditionalUnattendContent
    from ._models_py3 import ApiEntityReference
    from ._models_py3 import ApiError
    from ._models_py3 import ApiErrorBase
    from ._models_py3 import AutomaticOSUpgradePolicy
    from ._models_py3 import AutomaticOSUpgradeProperties
    from ._models_py3 import AutomaticRepairsPolicy
    from ._models_py3 import AvailabilitySet
    from ._models_py3 import AvailabilitySetUpdate
    from ._models_py3 import BillingProfile
    from ._models_py3 import BootDiagnostics
    from ._models_py3 import BootDiagnosticsInstanceView
    from ._models_py3 import ComputeOperationValue
    from ._models_py3 import CreationData
    from ._models_py3 import DataDisk
    from ._models_py3 import DataDiskImage
    from ._models_py3 import DedicatedHost
    from ._models_py3 import DedicatedHostAllocatableVM
    from ._models_py3 import DedicatedHostAvailableCapacity
    from ._models_py3 import DedicatedHostGroup
    from ._models_py3 import DedicatedHostGroupUpdate
    from ._models_py3 import DedicatedHostInstanceView
    from ._models_py3 import DedicatedHostUpdate
    from ._models_py3 import DiagnosticsProfile
    from ._models_py3 import DiffDiskSettings
    from ._models_py3 import Disallowed
    from ._models_py3 import Disk
    from ._models_py3 import DiskEncryptionSettings
    from ._models_py3 import DiskInstanceView
    from ._models_py3 import DiskSku
    from ._models_py3 import DiskUpdate
    from ._models_py3 import EncryptionSettingsCollection
    from ._models_py3 import EncryptionSettingsElement
    from ._models_py3 import Gallery
    from ._models_py3 import GalleryApplication
    from ._models_py3 import GalleryApplicationVersion
    from ._models_py3 import GalleryApplicationVersionPublishingProfile
    from ._models_py3 import GalleryArtifactPublishingProfileBase
    from ._models_py3 import GalleryArtifactSource
    from ._models_py3 import GalleryDataDiskImage
    from ._models_py3 import GalleryDiskImage
    from ._models_py3 import GalleryIdentifier
    from ._models_py3 import GalleryImage
    from ._models_py3 import GalleryImageIdentifier
    from ._models_py3 import GalleryImageVersion
    from ._models_py3 import GalleryImageVersionPublishingProfile
    from ._models_py3 import GalleryImageVersionStorageProfile
    from ._models_py3 import GalleryOSDiskImage
    from ._models_py3 import GrantAccessData
    from ._models_py3 import HardwareProfile
    from ._models_py3 import Image
    from ._models_py3 import ImageDataDisk
    from ._models_py3 import ImageDiskReference
    from ._models_py3 import ImageOSDisk
    from ._models_py3 import ImagePurchasePlan
    from ._models_py3 import ImageReference
    from ._models_py3 import ImageStorageProfile
    from ._models_py3 import ImageUpdate
    from ._models_py3 import InnerError
    from ._models_py3 import InstanceViewStatus
    from ._models_py3 import KeyVaultAndKeyReference
    from ._models_py3 import KeyVaultAndSecretReference
    from ._models_py3 import KeyVaultKeyReference
    from ._models_py3 import KeyVaultSecretReference
    from ._models_py3 import LinuxConfiguration
    from ._models_py3 import LogAnalyticsInputBase
    from ._models_py3 import LogAnalyticsOperationResult
    from ._models_py3 import LogAnalyticsOutput
    from ._models_py3 import MaintenanceRedeployStatus
    from ._models_py3 import ManagedArtifact
    from ._models_py3 import ManagedDiskParameters
    from ._models_py3 import NetworkInterfaceReference
    from ._models_py3 import NetworkProfile
    from ._models_py3 import OSDisk
    from ._models_py3 import OSDiskImage
    from ._models_py3 import OSProfile
    from ._models_py3 import Plan
    from ._models_py3 import ProximityPlacementGroup
    from ._models_py3 import ProximityPlacementGroupUpdate
    from ._models_py3 import PurchasePlan
    from ._models_py3 import RecommendedMachineConfiguration
    from ._models_py3 import RecoveryWalkResponse
    from ._models_py3 import RegionalReplicationStatus
    from ._models_py3 import ReplicationStatus
    from ._models_py3 import RequestRateByIntervalInput
    from ._models_py3 import Resource
    from ._models_py3 import ResourceRange
    from ._models_py3 import RollbackStatusInfo
    from ._models_py3 import RollingUpgradePolicy
    from ._models_py3 import RollingUpgradeProgressInfo
    from ._models_py3 import RollingUpgradeRunningStatus
    from ._models_py3 import RollingUpgradeStatusInfo
    from ._models_py3 import RunCommandDocument
    from ._models_py3 import RunCommandDocumentBase
    from ._models_py3 import RunCommandInput
    from ._models_py3 import RunCommandInputParameter
    from ._models_py3 import RunCommandParameterDefinition
    from ._models_py3 import RunCommandResult
    from ._models_py3 import ScaleInPolicy
    from ._models_py3 import ScheduledEventsProfile
    from ._models_py3 import Sku
    from ._models_py3 import Snapshot
    from ._models_py3 import SnapshotSku
    from ._models_py3 import SnapshotUpdate
    from ._models_py3 import SourceVault
    from ._models_py3 import SshConfiguration
    from ._models_py3 import SshPublicKey
    from ._models_py3 import StorageProfile
    from ._models_py3 import SubResource
    from ._models_py3 import SubResourceReadOnly
    from ._models_py3 import TargetRegion
    from ._models_py3 import TerminateNotificationProfile
    from ._models_py3 import ThrottledRequestsInput
    from ._models_py3 import UpdateResource
    from ._models_py3 import UpgradeOperationHistoricalStatusInfo
    from ._models_py3 import UpgradeOperationHistoricalStatusInfoProperties
    from ._models_py3 import UpgradeOperationHistoryStatus
    from ._models_py3 import UpgradePolicy
    from ._models_py3 import Usage
    from ._models_py3 import UsageName
    from ._models_py3 import UserArtifactSource
    from ._models_py3 import VaultCertificate
    from ._models_py3 import VaultSecretGroup
    from ._models_py3 import VirtualHardDisk
    from ._models_py3 import VirtualMachine
    from ._models_py3 import VirtualMachineAgentInstanceView
    from ._models_py3 import VirtualMachineCaptureParameters
    from ._models_py3 import VirtualMachineCaptureResult
    from ._models_py3 import VirtualMachineExtension
    from ._models_py3 import VirtualMachineExtensionHandlerInstanceView
    from ._models_py3 import VirtualMachineExtensionImage
    from ._models_py3 import VirtualMachineExtensionInstanceView
    from ._models_py3 import VirtualMachineExtensionsListResult
    from ._models_py3 import VirtualMachineExtensionUpdate
    from ._models_py3 import VirtualMachineHealthStatus
    from ._models_py3 import VirtualMachineIdentity
    from ._models_py3 import VirtualMachineIdentityUserAssignedIdentitiesValue
    from ._models_py3 import VirtualMachineImage
    from ._models_py3 import VirtualMachineImageResource
    from ._models_py3 import VirtualMachineInstanceView
    from ._models_py3 import VirtualMachineReimageParameters
    from ._models_py3 import VirtualMachineScaleSet
    from ._models_py3 import VirtualMachineScaleSetDataDisk
    from ._models_py3 import VirtualMachineScaleSetExtension
    from ._models_py3 import VirtualMachineScaleSetExtensionProfile
    from ._models_py3 import VirtualMachineScaleSetIdentity
    from ._models_py3 import VirtualMachineScaleSetIdentityUserAssignedIdentitiesValue
    from ._models_py3 import VirtualMachineScaleSetInstanceView
    from ._models_py3 import VirtualMachineScaleSetInstanceViewStatusesSummary
    from ._models_py3 import VirtualMachineScaleSetIPConfiguration
    from ._models_py3 import VirtualMachineScaleSetIpTag
    from ._models_py3 import VirtualMachineScaleSetManagedDiskParameters
    from ._models_py3 import VirtualMachineScaleSetNetworkConfiguration
    from ._models_py3 import VirtualMachineScaleSetNetworkConfigurationDnsSettings
    from ._models_py3 import VirtualMachineScaleSetNetworkProfile
    from ._models_py3 import VirtualMachineScaleSetOSDisk
    from ._models_py3 import VirtualMachineScaleSetOSProfile
    from ._models_py3 import VirtualMachineScaleSetPublicIPAddressConfiguration
    from ._models_py3 import VirtualMachineScaleSetPublicIPAddressConfigurationDnsSettings
    from ._models_py3 import VirtualMachineScaleSetReimageParameters
    from ._models_py3 import VirtualMachineScaleSetSku
    from ._models_py3 import VirtualMachineScaleSetSkuCapacity
    from ._models_py3 import VirtualMachineScaleSetStorageProfile
    from ._models_py3 import VirtualMachineScaleSetUpdate
    from ._models_py3 import VirtualMachineScaleSetUpdateIPConfiguration
    from ._models_py3 import VirtualMachineScaleSetUpdateNetworkConfiguration
    from ._models_py3 import VirtualMachineScaleSetUpdateNetworkProfile
    from ._models_py3 import VirtualMachineScaleSetUpdateOSDisk
    from ._models_py3 import VirtualMachineScaleSetUpdateOSProfile
    from ._models_py3 import VirtualMachineScaleSetUpdatePublicIPAddressConfiguration
    from ._models_py3 import VirtualMachineScaleSetUpdateStorageProfile
    from ._models_py3 import VirtualMachineScaleSetUpdateVMProfile
    from ._models_py3 import VirtualMachineScaleSetVM
    from ._models_py3 import VirtualMachineScaleSetVMExtensionsSummary
    from ._models_py3 import VirtualMachineScaleSetVMInstanceIDs
    from ._models_py3 import VirtualMachineScaleSetVMInstanceRequiredIDs
    from ._models_py3 import VirtualMachineScaleSetVMInstanceView
    from ._models_py3 import VirtualMachineScaleSetVMNetworkProfileConfiguration
    from ._models_py3 import VirtualMachineScaleSetVMProfile
    from ._models_py3 import VirtualMachineScaleSetVMProtectionPolicy
    from ._models_py3 import VirtualMachineScaleSetVMReimageParameters
    from ._models_py3 import VirtualMachineSize
    from ._models_py3 import VirtualMachineStatusCodeCount
    from ._models_py3 import VirtualMachineUpdate
    from ._models_py3 import VMScaleSetConvertToSinglePlacementGroupInput
    from ._models_py3 import WindowsConfiguration
    from ._models_py3 import WinRMConfiguration
    from ._models_py3 import WinRMListener
except (SyntaxError, ImportError):
    from ._models import AccessUri
    from ._models import AdditionalCapabilities
    from ._models import AdditionalUnattendContent
    from ._models import ApiEntityReference
    from ._models import ApiError
    from ._models import ApiErrorBase
    from ._models import AutomaticOSUpgradePolicy
    from ._models import AutomaticOSUpgradeProperties
    from ._models import AutomaticRepairsPolicy
    from ._models import AvailabilitySet
    from ._models import AvailabilitySetUpdate
    from ._models import BillingProfile
    from ._models import BootDiagnostics
    from ._models import BootDiagnosticsInstanceView
    from ._models import ComputeOperationValue
    from ._models import CreationData
    from ._models import DataDisk
    from ._models import DataDiskImage
    from ._models import DedicatedHost
    from ._models import DedicatedHostAllocatableVM
    from ._models import DedicatedHostAvailableCapacity
    from ._models import DedicatedHostGroup
    from ._models import DedicatedHostGroupUpdate
    from ._models import DedicatedHostInstanceView
    from ._models import DedicatedHostUpdate
    from ._models import DiagnosticsProfile
    from ._models import DiffDiskSettings
    from ._models import Disallowed
    from ._models import Disk
    from ._models import DiskEncryptionSettings
    from ._models import DiskInstanceView
    from ._models import DiskSku
    from ._models import DiskUpdate
    from ._models import EncryptionSettingsCollection
    from ._models import EncryptionSettingsElement
    from ._models import Gallery
    from ._models import GalleryApplication
    from ._models import GalleryApplicationVersion
    from ._models import GalleryApplicationVersionPublishingProfile
    from ._models import GalleryArtifactPublishingProfileBase
    from ._models import GalleryArtifactSource
    from ._models import GalleryDataDiskImage
    from ._models import GalleryDiskImage
    from ._models import GalleryIdentifier
    from ._models import GalleryImage
    from ._models import GalleryImageIdentifier
    from ._models import GalleryImageVersion
    from ._models import GalleryImageVersionPublishingProfile
    from ._models import GalleryImageVersionStorageProfile
    from ._models import GalleryOSDiskImage
    from ._models import GrantAccessData
    from ._models import HardwareProfile
    from ._models import Image
    from ._models import ImageDataDisk
    from ._models import ImageDiskReference
    from ._models import ImageOSDisk
    from ._models import ImagePurchasePlan
    from ._models import ImageReference
    from ._models import ImageStorageProfile
    from ._models import ImageUpdate
    from ._models import InnerError
    from ._models import InstanceViewStatus
    from ._models import KeyVaultAndKeyReference
    from ._models import KeyVaultAndSecretReference
    from ._models import KeyVaultKeyReference
    from ._models import KeyVaultSecretReference
    from ._models import LinuxConfiguration
    from ._models import LogAnalyticsInputBase
    from ._models import LogAnalyticsOperationResult
    from ._models import LogAnalyticsOutput
    from ._models import MaintenanceRedeployStatus
    from ._models import ManagedArtifact
    from ._models import ManagedDiskParameters
    from ._models import NetworkInterfaceReference
    from ._models import NetworkProfile
    from ._models import OSDisk
    from ._models import OSDiskImage
    from ._models import OSProfile
    from ._models import Plan
    from ._models import ProximityPlacementGroup
    from ._models import ProximityPlacementGroupUpdate
    from ._models import PurchasePlan
    from ._models import RecommendedMachineConfiguration
    from ._models import RecoveryWalkResponse
    from ._models import RegionalReplicationStatus
    from ._models import ReplicationStatus
    from ._models import RequestRateByIntervalInput
    from ._models import Resource
    from ._models import ResourceRange
    from ._models import RollbackStatusInfo
    from ._models import RollingUpgradePolicy
    from ._models import RollingUpgradeProgressInfo
    from ._models import RollingUpgradeRunningStatus
    from ._models import RollingUpgradeStatusInfo
    from ._models import RunCommandDocument
    from ._models import RunCommandDocumentBase
    from ._models import RunCommandInput
    from ._models import RunCommandInputParameter
    from ._models import RunCommandParameterDefinition
    from ._models import RunCommandResult
    from ._models import ScaleInPolicy
    from ._models import ScheduledEventsProfile
    from ._models import Sku
    from ._models import Snapshot
    from ._models import SnapshotSku
    from ._models import SnapshotUpdate
    from ._models import SourceVault
    from ._models import SshConfiguration
    from ._models import SshPublicKey
    from ._models import StorageProfile
    from ._models import SubResource
    from ._models import SubResourceReadOnly
    from ._models import TargetRegion
    from ._models import TerminateNotificationProfile
    from ._models import ThrottledRequestsInput
    from ._models import UpdateResource
    from ._models import UpgradeOperationHistoricalStatusInfo
    from ._models import UpgradeOperationHistoricalStatusInfoProperties
    from ._models import UpgradeOperationHistoryStatus
    from ._models import UpgradePolicy
    from ._models import Usage
    from ._models import UsageName
    from ._models import UserArtifactSource
    from ._models import VaultCertificate
    from ._models import VaultSecretGroup
    from ._models import VirtualHardDisk
    from ._models import VirtualMachine
    from ._models import VirtualMachineAgentInstanceView
    from ._models import VirtualMachineCaptureParameters
    from ._models import VirtualMachineCaptureResult
    from ._models import VirtualMachineExtension
    from ._models import VirtualMachineExtensionHandlerInstanceView
    from ._models import VirtualMachineExtensionImage
    from ._models import VirtualMachineExtensionInstanceView
    from ._models import VirtualMachineExtensionsListResult
    from ._models import VirtualMachineExtensionUpdate
    from ._models import VirtualMachineHealthStatus
    from ._models import VirtualMachineIdentity
    from ._models import VirtualMachineIdentityUserAssignedIdentitiesValue
    from ._models import VirtualMachineImage
    from ._models import VirtualMachineImageResource
    from ._models import VirtualMachineInstanceView
    from ._models import VirtualMachineReimageParameters
    from ._models import VirtualMachineScaleSet
    from ._models import VirtualMachineScaleSetDataDisk
    from ._models import VirtualMachineScaleSetExtension
    from ._models import VirtualMachineScaleSetExtensionProfile
    from ._models import VirtualMachineScaleSetIdentity
    from ._models import VirtualMachineScaleSetIdentityUserAssignedIdentitiesValue
    from ._models import VirtualMachineScaleSetInstanceView
    from ._models import VirtualMachineScaleSetInstanceViewStatusesSummary
    from ._models import VirtualMachineScaleSetIPConfiguration
    from ._models import VirtualMachineScaleSetIpTag
    from ._models import VirtualMachineScaleSetManagedDiskParameters
    from ._models import VirtualMachineScaleSetNetworkConfiguration
    from ._models import VirtualMachineScaleSetNetworkConfigurationDnsSettings
    from ._models import VirtualMachineScaleSetNetworkProfile
    from ._models import VirtualMachineScaleSetOSDisk
    from ._models import VirtualMachineScaleSetOSProfile
    from ._models import VirtualMachineScaleSetPublicIPAddressConfiguration
    from ._models import VirtualMachineScaleSetPublicIPAddressConfigurationDnsSettings
    from ._models import VirtualMachineScaleSetReimageParameters
    from ._models import VirtualMachineScaleSetSku
    from ._models import VirtualMachineScaleSetSkuCapacity
    from ._models import VirtualMachineScaleSetStorageProfile
    from ._models import VirtualMachineScaleSetUpdate
    from ._models import VirtualMachineScaleSetUpdateIPConfiguration
    from ._models import VirtualMachineScaleSetUpdateNetworkConfiguration
    from ._models import VirtualMachineScaleSetUpdateNetworkProfile
    from ._models import VirtualMachineScaleSetUpdateOSDisk
    from ._models import VirtualMachineScaleSetUpdateOSProfile
    from ._models import VirtualMachineScaleSetUpdatePublicIPAddressConfiguration
    from ._models import VirtualMachineScaleSetUpdateStorageProfile
    from ._models import VirtualMachineScaleSetUpdateVMProfile
    from ._models import VirtualMachineScaleSetVM
    from ._models import VirtualMachineScaleSetVMExtensionsSummary
    from ._models import VirtualMachineScaleSetVMInstanceIDs
    from ._models import VirtualMachineScaleSetVMInstanceRequiredIDs
    from ._models import VirtualMachineScaleSetVMInstanceView
    from ._models import VirtualMachineScaleSetVMNetworkProfileConfiguration
    from ._models import VirtualMachineScaleSetVMProfile
    from ._models import VirtualMachineScaleSetVMProtectionPolicy
    from ._models import VirtualMachineScaleSetVMReimageParameters
    from ._models import VirtualMachineSize
    from ._models import VirtualMachineStatusCodeCount
    from ._models import VirtualMachineUpdate
    from ._models import VMScaleSetConvertToSinglePlacementGroupInput
    from ._models import WindowsConfiguration
    from ._models import WinRMConfiguration
    from ._models import WinRMListener
from ._paged_models import AvailabilitySetPaged
from ._paged_models import ComputeOperationValuePaged
from ._paged_models import DedicatedHostGroupPaged
from ._paged_models import DedicatedHostPaged
from ._paged_models import DiskPaged
from ._paged_models import GalleryApplicationPaged
from ._paged_models import GalleryApplicationVersionPaged
from ._paged_models import GalleryImagePaged
from ._paged_models import GalleryImageVersionPaged
from ._paged_models import GalleryPaged
from ._paged_models import ImagePaged
from ._paged_models import ProximityPlacementGroupPaged
from ._paged_models import RunCommandDocumentBasePaged
from ._paged_models import SnapshotPaged
from ._paged_models import UpgradeOperationHistoricalStatusInfoPaged
from ._paged_models import UsagePaged
from ._paged_models import VirtualMachinePaged
from ._paged_models import VirtualMachineScaleSetExtensionPaged
from ._paged_models import VirtualMachineScaleSetPaged
from ._paged_models import VirtualMachineScaleSetSkuPaged
from ._paged_models import VirtualMachineScaleSetVMPaged
from ._paged_models import VirtualMachineSizePaged
from ._compute_management_client_enums import (
    HyperVGenerationTypes,
    StatusLevelTypes,
    AvailabilitySetSkuTypes,
    ProximityPlacementGroupType,
    DedicatedHostLicenseTypes,
    OperatingSystemTypes,
    VirtualMachineSizeTypes,
    CachingTypes,
    DiskCreateOptionTypes,
    StorageAccountTypes,
    DiffDiskOptions,
    PassNames,
    ComponentNames,
    SettingNames,
    ProtocolTypes,
    VirtualMachinePriorityTypes,
    VirtualMachineEvictionPolicyTypes,
    ResourceIdentityType,
    MaintenanceOperationResultCodeTypes,
    HyperVGenerationType,
    UpgradeMode,
    VirtualMachineScaleSetScaleInRules,
    OperatingSystemStateTypes,
    IPVersion,
    VirtualMachineScaleSetSkuScaleType,
    UpgradeState,
    UpgradeOperationInvoker,
    RollingUpgradeStatusCode,
    RollingUpgradeActionType,
    IntervalInMins,
    AggregatedReplicationState,
    ReplicationState,
    StorageAccountType,
    HostCaching,
    DiskStorageAccountTypes,
    HyperVGeneration,
    DiskCreateOption,
    DiskState,
    SnapshotStorageAccountTypes,
    AccessLevel,
    InstanceViewTypes,
    ReplicationStatusTypes,
)

__all__ = [
    'AccessUri',
    'AdditionalCapabilities',
    'AdditionalUnattendContent',
    'ApiEntityReference',
    'ApiError',
    'ApiErrorBase',
    'AutomaticOSUpgradePolicy',
    'AutomaticOSUpgradeProperties',
    'AutomaticRepairsPolicy',
    'AvailabilitySet',
    'AvailabilitySetUpdate',
    'BillingProfile',
    'BootDiagnostics',
    'BootDiagnosticsInstanceView',
    'ComputeOperationValue',
    'CreationData',
    'DataDisk',
    'DataDiskImage',
    'DedicatedHost',
    'DedicatedHostAllocatableVM',
    'DedicatedHostAvailableCapacity',
    'DedicatedHostGroup',
    'DedicatedHostGroupUpdate',
    'DedicatedHostInstanceView',
    'DedicatedHostUpdate',
    'DiagnosticsProfile',
    'DiffDiskSettings',
    'Disallowed',
    'Disk',
    'DiskEncryptionSettings',
    'DiskInstanceView',
    'DiskSku',
    'DiskUpdate',
    'EncryptionSettingsCollection',
    'EncryptionSettingsElement',
    'Gallery',
    'GalleryApplication',
    'GalleryApplicationVersion',
    'GalleryApplicationVersionPublishingProfile',
    'GalleryArtifactPublishingProfileBase',
    'GalleryArtifactSource',
    'GalleryDataDiskImage',
    'GalleryDiskImage',
    'GalleryIdentifier',
    'GalleryImage',
    'GalleryImageIdentifier',
    'GalleryImageVersion',
    'GalleryImageVersionPublishingProfile',
    'GalleryImageVersionStorageProfile',
    'GalleryOSDiskImage',
    'GrantAccessData',
    'HardwareProfile',
    'Image',
    'ImageDataDisk',
    'ImageDiskReference',
    'ImageOSDisk',
    'ImagePurchasePlan',
    'ImageReference',
    'ImageStorageProfile',
    'ImageUpdate',
    'InnerError',
    'InstanceViewStatus',
    'KeyVaultAndKeyReference',
    'KeyVaultAndSecretReference',
    'KeyVaultKeyReference',
    'KeyVaultSecretReference',
    'LinuxConfiguration',
    'LogAnalyticsInputBase',
    'LogAnalyticsOperationResult',
    'LogAnalyticsOutput',
    'MaintenanceRedeployStatus',
    'ManagedArtifact',
    'ManagedDiskParameters',
    'NetworkInterfaceReference',
    'NetworkProfile',
    'OSDisk',
    'OSDiskImage',
    'OSProfile',
    'Plan',
    'ProximityPlacementGroup',
    'ProximityPlacementGroupUpdate',
    'PurchasePlan',
    'RecommendedMachineConfiguration',
    'RecoveryWalkResponse',
    'RegionalReplicationStatus',
    'ReplicationStatus',
    'RequestRateByIntervalInput',
    'Resource',
    'ResourceRange',
    'RollbackStatusInfo',
    'RollingUpgradePolicy',
    'RollingUpgradeProgressInfo',
    'RollingUpgradeRunningStatus',
    'RollingUpgradeStatusInfo',
    'RunCommandDocument',
    'RunCommandDocumentBase',
    'RunCommandInput',
    'RunCommandInputParameter',
    'RunCommandParameterDefinition',
    'RunCommandResult',
    'ScaleInPolicy',
    'ScheduledEventsProfile',
    'Sku',
    'Snapshot',
    'SnapshotSku',
    'SnapshotUpdate',
    'SourceVault',
    'SshConfiguration',
    'SshPublicKey',
    'StorageProfile',
    'SubResource',
    'SubResourceReadOnly',
    'TargetRegion',
    'TerminateNotificationProfile',
    'ThrottledRequestsInput',
    'UpdateResource',
    'UpgradeOperationHistoricalStatusInfo',
    'UpgradeOperationHistoricalStatusInfoProperties',
    'UpgradeOperationHistoryStatus',
    'UpgradePolicy',
    'Usage',
    'UsageName',
    'UserArtifactSource',
    'VaultCertificate',
    'VaultSecretGroup',
    'VirtualHardDisk',
    'VirtualMachine',
    'VirtualMachineAgentInstanceView',
    'VirtualMachineCaptureParameters',
    'VirtualMachineCaptureResult',
    'VirtualMachineExtension',
    'VirtualMachineExtensionHandlerInstanceView',
    'VirtualMachineExtensionImage',
    'VirtualMachineExtensionInstanceView',
    'VirtualMachineExtensionsListResult',
    'VirtualMachineExtensionUpdate',
    'VirtualMachineHealthStatus',
    'VirtualMachineIdentity',
    'VirtualMachineIdentityUserAssignedIdentitiesValue',
    'VirtualMachineImage',
    'VirtualMachineImageResource',
    'VirtualMachineInstanceView',
    'VirtualMachineReimageParameters',
    'VirtualMachineScaleSet',
    'VirtualMachineScaleSetDataDisk',
    'VirtualMachineScaleSetExtension',
    'VirtualMachineScaleSetExtensionProfile',
    'VirtualMachineScaleSetIdentity',
    'VirtualMachineScaleSetIdentityUserAssignedIdentitiesValue',
    'VirtualMachineScaleSetInstanceView',
    'VirtualMachineScaleSetInstanceViewStatusesSummary',
    'VirtualMachineScaleSetIPConfiguration',
    'VirtualMachineScaleSetIpTag',
    'VirtualMachineScaleSetManagedDiskParameters',
    'VirtualMachineScaleSetNetworkConfiguration',
    'VirtualMachineScaleSetNetworkConfigurationDnsSettings',
    'VirtualMachineScaleSetNetworkProfile',
    'VirtualMachineScaleSetOSDisk',
    'VirtualMachineScaleSetOSProfile',
    'VirtualMachineScaleSetPublicIPAddressConfiguration',
    'VirtualMachineScaleSetPublicIPAddressConfigurationDnsSettings',
    'VirtualMachineScaleSetReimageParameters',
    'VirtualMachineScaleSetSku',
    'VirtualMachineScaleSetSkuCapacity',
    'VirtualMachineScaleSetStorageProfile',
    'VirtualMachineScaleSetUpdate',
    'VirtualMachineScaleSetUpdateIPConfiguration',
    'VirtualMachineScaleSetUpdateNetworkConfiguration',
    'VirtualMachineScaleSetUpdateNetworkProfile',
    'VirtualMachineScaleSetUpdateOSDisk',
    'VirtualMachineScaleSetUpdateOSProfile',
    'VirtualMachineScaleSetUpdatePublicIPAddressConfiguration',
    'VirtualMachineScaleSetUpdateStorageProfile',
    'VirtualMachineScaleSetUpdateVMProfile',
    'VirtualMachineScaleSetVM',
    'VirtualMachineScaleSetVMExtensionsSummary',
    'VirtualMachineScaleSetVMInstanceIDs',
    'VirtualMachineScaleSetVMInstanceRequiredIDs',
    'VirtualMachineScaleSetVMInstanceView',
    'VirtualMachineScaleSetVMNetworkProfileConfiguration',
    'VirtualMachineScaleSetVMProfile',
    'VirtualMachineScaleSetVMProtectionPolicy',
    'VirtualMachineScaleSetVMReimageParameters',
    'VirtualMachineSize',
    'VirtualMachineStatusCodeCount',
    'VirtualMachineUpdate',
    'VMScaleSetConvertToSinglePlacementGroupInput',
    'WindowsConfiguration',
    'WinRMConfiguration',
    'WinRMListener',
    'ComputeOperationValuePaged',
    'AvailabilitySetPaged',
    'VirtualMachineSizePaged',
    'ProximityPlacementGroupPaged',
    'DedicatedHostGroupPaged',
    'DedicatedHostPaged',
    'UsagePaged',
    'VirtualMachinePaged',
    'ImagePaged',
    'VirtualMachineScaleSetPaged',
    'VirtualMachineScaleSetSkuPaged',
    'UpgradeOperationHistoricalStatusInfoPaged',
    'VirtualMachineScaleSetExtensionPaged',
    'VirtualMachineScaleSetVMPaged',
    'RunCommandDocumentBasePaged',
    'GalleryPaged',
    'GalleryImagePaged',
    'GalleryImageVersionPaged',
    'GalleryApplicationPaged',
    'GalleryApplicationVersionPaged',
    'DiskPaged',
    'SnapshotPaged',
    'HyperVGenerationTypes',
    'StatusLevelTypes',
    'AvailabilitySetSkuTypes',
    'ProximityPlacementGroupType',
    'DedicatedHostLicenseTypes',
    'OperatingSystemTypes',
    'VirtualMachineSizeTypes',
    'CachingTypes',
    'DiskCreateOptionTypes',
    'StorageAccountTypes',
    'DiffDiskOptions',
    'PassNames',
    'ComponentNames',
    'SettingNames',
    'ProtocolTypes',
    'VirtualMachinePriorityTypes',
    'VirtualMachineEvictionPolicyTypes',
    'ResourceIdentityType',
    'MaintenanceOperationResultCodeTypes',
    'HyperVGenerationType',
    'UpgradeMode',
    'VirtualMachineScaleSetScaleInRules',
    'OperatingSystemStateTypes',
    'IPVersion',
    'VirtualMachineScaleSetSkuScaleType',
    'UpgradeState',
    'UpgradeOperationInvoker',
    'RollingUpgradeStatusCode',
    'RollingUpgradeActionType',
    'IntervalInMins',
    'AggregatedReplicationState',
    'ReplicationState',
    'StorageAccountType',
    'HostCaching',
    'DiskStorageAccountTypes',
    'HyperVGeneration',
    'DiskCreateOption',
    'DiskState',
    'SnapshotStorageAccountTypes',
    'AccessLevel',
    'InstanceViewTypes',
    'ReplicationStatusTypes',
]
