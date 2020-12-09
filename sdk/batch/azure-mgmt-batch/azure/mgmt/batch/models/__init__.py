# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import ActivateApplicationPackageParameters
    from ._models_py3 import Application
    from ._models_py3 import ApplicationPackage
    from ._models_py3 import ApplicationPackageReference
    from ._models_py3 import AutoScaleRun
    from ._models_py3 import AutoScaleRunError
    from ._models_py3 import AutoScaleSettings
    from ._models_py3 import AutoStorageBaseProperties
    from ._models_py3 import AutoStorageProperties
    from ._models_py3 import AutoUserSpecification
    from ._models_py3 import AzureBlobFileSystemConfiguration
    from ._models_py3 import AzureFileShareConfiguration
    from ._models_py3 import BatchAccount
    from ._models_py3 import BatchAccountCreateParameters
    from ._models_py3 import BatchAccountIdentity
    from ._models_py3 import BatchAccountKeys
    from ._models_py3 import BatchAccountListResult
    from ._models_py3 import BatchAccountRegenerateKeyParameters
    from ._models_py3 import BatchAccountUpdateParameters
    from ._models_py3 import BatchLocationQuota
    from ._models_py3 import CIFSMountConfiguration
    from ._models_py3 import Certificate
    from ._models_py3 import CertificateBaseProperties
    from ._models_py3 import CertificateCreateOrUpdateParameters
    from ._models_py3 import CertificateCreateOrUpdateProperties
    from ._models_py3 import CertificateProperties
    from ._models_py3 import CertificateReference
    from ._models_py3 import CheckNameAvailabilityParameters
    from ._models_py3 import CheckNameAvailabilityResult
    from ._models_py3 import CloudErrorBody
    from ._models_py3 import CloudServiceConfiguration
    from ._models_py3 import ContainerConfiguration
    from ._models_py3 import ContainerRegistry
    from ._models_py3 import DataDisk
    from ._models_py3 import DeleteCertificateError
    from ._models_py3 import DeploymentConfiguration
    from ._models_py3 import DiskEncryptionConfiguration
    from ._models_py3 import EncryptionProperties
    from ._models_py3 import EnvironmentSetting
    from ._models_py3 import FixedScaleSettings
    from ._models_py3 import ImageReference
    from ._models_py3 import InboundNatPool
    from ._models_py3 import KeyVaultProperties
    from ._models_py3 import KeyVaultReference
    from ._models_py3 import LinuxUserConfiguration
    from ._models_py3 import ListApplicationPackagesResult
    from ._models_py3 import ListApplicationsResult
    from ._models_py3 import ListCertificatesResult
    from ._models_py3 import ListPoolsResult
    from ._models_py3 import ListPrivateEndpointConnectionsResult
    from ._models_py3 import ListPrivateLinkResourcesResult
    from ._models_py3 import MetadataItem
    from ._models_py3 import MountConfiguration
    from ._models_py3 import NFSMountConfiguration
    from ._models_py3 import NetworkConfiguration
    from ._models_py3 import NetworkSecurityGroupRule
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationListResult
    from ._models_py3 import Pool
    from ._models_py3 import PoolEndpointConfiguration
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import ProxyResource
    from ._models_py3 import PublicIPAddressConfiguration
    from ._models_py3 import ResizeError
    from ._models_py3 import ResizeOperationStatus
    from ._models_py3 import Resource
    from ._models_py3 import ResourceFile
    from ._models_py3 import ScaleSettings
    from ._models_py3 import StartTask
    from ._models_py3 import TaskContainerSettings
    from ._models_py3 import TaskSchedulingPolicy
    from ._models_py3 import UserAccount
    from ._models_py3 import UserIdentity
    from ._models_py3 import VirtualMachineConfiguration
    from ._models_py3 import VirtualMachineFamilyCoreQuota
    from ._models_py3 import WindowsConfiguration
    from ._models_py3 import WindowsUserConfiguration
except (SyntaxError, ImportError):
    from ._models import ActivateApplicationPackageParameters  # type: ignore
    from ._models import Application  # type: ignore
    from ._models import ApplicationPackage  # type: ignore
    from ._models import ApplicationPackageReference  # type: ignore
    from ._models import AutoScaleRun  # type: ignore
    from ._models import AutoScaleRunError  # type: ignore
    from ._models import AutoScaleSettings  # type: ignore
    from ._models import AutoStorageBaseProperties  # type: ignore
    from ._models import AutoStorageProperties  # type: ignore
    from ._models import AutoUserSpecification  # type: ignore
    from ._models import AzureBlobFileSystemConfiguration  # type: ignore
    from ._models import AzureFileShareConfiguration  # type: ignore
    from ._models import BatchAccount  # type: ignore
    from ._models import BatchAccountCreateParameters  # type: ignore
    from ._models import BatchAccountIdentity  # type: ignore
    from ._models import BatchAccountKeys  # type: ignore
    from ._models import BatchAccountListResult  # type: ignore
    from ._models import BatchAccountRegenerateKeyParameters  # type: ignore
    from ._models import BatchAccountUpdateParameters  # type: ignore
    from ._models import BatchLocationQuota  # type: ignore
    from ._models import CIFSMountConfiguration  # type: ignore
    from ._models import Certificate  # type: ignore
    from ._models import CertificateBaseProperties  # type: ignore
    from ._models import CertificateCreateOrUpdateParameters  # type: ignore
    from ._models import CertificateCreateOrUpdateProperties  # type: ignore
    from ._models import CertificateProperties  # type: ignore
    from ._models import CertificateReference  # type: ignore
    from ._models import CheckNameAvailabilityParameters  # type: ignore
    from ._models import CheckNameAvailabilityResult  # type: ignore
    from ._models import CloudErrorBody  # type: ignore
    from ._models import CloudServiceConfiguration  # type: ignore
    from ._models import ContainerConfiguration  # type: ignore
    from ._models import ContainerRegistry  # type: ignore
    from ._models import DataDisk  # type: ignore
    from ._models import DeleteCertificateError  # type: ignore
    from ._models import DeploymentConfiguration  # type: ignore
    from ._models import DiskEncryptionConfiguration  # type: ignore
    from ._models import EncryptionProperties  # type: ignore
    from ._models import EnvironmentSetting  # type: ignore
    from ._models import FixedScaleSettings  # type: ignore
    from ._models import ImageReference  # type: ignore
    from ._models import InboundNatPool  # type: ignore
    from ._models import KeyVaultProperties  # type: ignore
    from ._models import KeyVaultReference  # type: ignore
    from ._models import LinuxUserConfiguration  # type: ignore
    from ._models import ListApplicationPackagesResult  # type: ignore
    from ._models import ListApplicationsResult  # type: ignore
    from ._models import ListCertificatesResult  # type: ignore
    from ._models import ListPoolsResult  # type: ignore
    from ._models import ListPrivateEndpointConnectionsResult  # type: ignore
    from ._models import ListPrivateLinkResourcesResult  # type: ignore
    from ._models import MetadataItem  # type: ignore
    from ._models import MountConfiguration  # type: ignore
    from ._models import NFSMountConfiguration  # type: ignore
    from ._models import NetworkConfiguration  # type: ignore
    from ._models import NetworkSecurityGroupRule  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import OperationListResult  # type: ignore
    from ._models import Pool  # type: ignore
    from ._models import PoolEndpointConfiguration  # type: ignore
    from ._models import PrivateEndpoint  # type: ignore
    from ._models import PrivateEndpointConnection  # type: ignore
    from ._models import PrivateLinkResource  # type: ignore
    from ._models import PrivateLinkServiceConnectionState  # type: ignore
    from ._models import ProxyResource  # type: ignore
    from ._models import PublicIPAddressConfiguration  # type: ignore
    from ._models import ResizeError  # type: ignore
    from ._models import ResizeOperationStatus  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceFile  # type: ignore
    from ._models import ScaleSettings  # type: ignore
    from ._models import StartTask  # type: ignore
    from ._models import TaskContainerSettings  # type: ignore
    from ._models import TaskSchedulingPolicy  # type: ignore
    from ._models import UserAccount  # type: ignore
    from ._models import UserIdentity  # type: ignore
    from ._models import VirtualMachineConfiguration  # type: ignore
    from ._models import VirtualMachineFamilyCoreQuota  # type: ignore
    from ._models import WindowsConfiguration  # type: ignore
    from ._models import WindowsUserConfiguration  # type: ignore

from ._batch_management_enums import (
    AccountKeyType,
    AllocationState,
    AutoUserScope,
    CachingType,
    CertificateFormat,
    CertificateProvisioningState,
    CertificateStoreLocation,
    CertificateVisibility,
    ComputeNodeDeallocationOption,
    ComputeNodeFillType,
    ContainerWorkingDirectory,
    DiskEncryptionTarget,
    ElevationLevel,
    IPAddressProvisioningType,
    InboundEndpointProtocol,
    InterNodeCommunicationState,
    KeySource,
    LoginMode,
    NameAvailabilityReason,
    NetworkSecurityGroupRuleAccess,
    PackageState,
    PoolAllocationMode,
    PoolProvisioningState,
    PrivateEndpointConnectionProvisioningState,
    PrivateLinkServiceConnectionStatus,
    ProvisioningState,
    PublicNetworkAccessType,
    ResourceIdentityType,
    StorageAccountType,
)

__all__ = [
    'ActivateApplicationPackageParameters',
    'Application',
    'ApplicationPackage',
    'ApplicationPackageReference',
    'AutoScaleRun',
    'AutoScaleRunError',
    'AutoScaleSettings',
    'AutoStorageBaseProperties',
    'AutoStorageProperties',
    'AutoUserSpecification',
    'AzureBlobFileSystemConfiguration',
    'AzureFileShareConfiguration',
    'BatchAccount',
    'BatchAccountCreateParameters',
    'BatchAccountIdentity',
    'BatchAccountKeys',
    'BatchAccountListResult',
    'BatchAccountRegenerateKeyParameters',
    'BatchAccountUpdateParameters',
    'BatchLocationQuota',
    'CIFSMountConfiguration',
    'Certificate',
    'CertificateBaseProperties',
    'CertificateCreateOrUpdateParameters',
    'CertificateCreateOrUpdateProperties',
    'CertificateProperties',
    'CertificateReference',
    'CheckNameAvailabilityParameters',
    'CheckNameAvailabilityResult',
    'CloudErrorBody',
    'CloudServiceConfiguration',
    'ContainerConfiguration',
    'ContainerRegistry',
    'DataDisk',
    'DeleteCertificateError',
    'DeploymentConfiguration',
    'DiskEncryptionConfiguration',
    'EncryptionProperties',
    'EnvironmentSetting',
    'FixedScaleSettings',
    'ImageReference',
    'InboundNatPool',
    'KeyVaultProperties',
    'KeyVaultReference',
    'LinuxUserConfiguration',
    'ListApplicationPackagesResult',
    'ListApplicationsResult',
    'ListCertificatesResult',
    'ListPoolsResult',
    'ListPrivateEndpointConnectionsResult',
    'ListPrivateLinkResourcesResult',
    'MetadataItem',
    'MountConfiguration',
    'NFSMountConfiguration',
    'NetworkConfiguration',
    'NetworkSecurityGroupRule',
    'Operation',
    'OperationDisplay',
    'OperationListResult',
    'Pool',
    'PoolEndpointConfiguration',
    'PrivateEndpoint',
    'PrivateEndpointConnection',
    'PrivateLinkResource',
    'PrivateLinkServiceConnectionState',
    'ProxyResource',
    'PublicIPAddressConfiguration',
    'ResizeError',
    'ResizeOperationStatus',
    'Resource',
    'ResourceFile',
    'ScaleSettings',
    'StartTask',
    'TaskContainerSettings',
    'TaskSchedulingPolicy',
    'UserAccount',
    'UserIdentity',
    'VirtualMachineConfiguration',
    'VirtualMachineFamilyCoreQuota',
    'WindowsConfiguration',
    'WindowsUserConfiguration',
    'AccountKeyType',
    'AllocationState',
    'AutoUserScope',
    'CachingType',
    'CertificateFormat',
    'CertificateProvisioningState',
    'CertificateStoreLocation',
    'CertificateVisibility',
    'ComputeNodeDeallocationOption',
    'ComputeNodeFillType',
    'ContainerWorkingDirectory',
    'DiskEncryptionTarget',
    'ElevationLevel',
    'IPAddressProvisioningType',
    'InboundEndpointProtocol',
    'InterNodeCommunicationState',
    'KeySource',
    'LoginMode',
    'NameAvailabilityReason',
    'NetworkSecurityGroupRuleAccess',
    'PackageState',
    'PoolAllocationMode',
    'PoolProvisioningState',
    'PrivateEndpointConnectionProvisioningState',
    'PrivateLinkServiceConnectionStatus',
    'ProvisioningState',
    'PublicNetworkAccessType',
    'ResourceIdentityType',
    'StorageAccountType',
]
