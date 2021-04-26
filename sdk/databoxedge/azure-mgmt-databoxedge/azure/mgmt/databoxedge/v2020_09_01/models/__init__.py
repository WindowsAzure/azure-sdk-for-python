# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import ARMBaseModel
    from ._models_py3 import Addon
    from ._models_py3 import AddonList
    from ._models_py3 import Address
    from ._models_py3 import Alert
    from ._models_py3 import AlertErrorDetails
    from ._models_py3 import AlertList
    from ._models_py3 import ArcAddon
    from ._models_py3 import AsymmetricEncryptedSecret
    from ._models_py3 import Authentication
    from ._models_py3 import AzureContainerInfo
    from ._models_py3 import BandwidthSchedule
    from ._models_py3 import BandwidthSchedulesList
    from ._models_py3 import ClientAccessRight
    from ._models_py3 import CloudEdgeManagementRole
    from ._models_py3 import CloudErrorBody
    from ._models_py3 import CniConfig
    from ._models_py3 import ComputeResource
    from ._models_py3 import ContactDetails
    from ._models_py3 import Container
    from ._models_py3 import ContainerList
    from ._models_py3 import DCAccessCode
    from ._models_py3 import DataBoxEdgeDevice
    from ._models_py3 import DataBoxEdgeDeviceExtendedInfo
    from ._models_py3 import DataBoxEdgeDeviceExtendedInfoPatch
    from ._models_py3 import DataBoxEdgeDeviceList
    from ._models_py3 import DataBoxEdgeDevicePatch
    from ._models_py3 import DataBoxEdgeMoveRequest
    from ._models_py3 import DataBoxEdgeSku
    from ._models_py3 import DataBoxEdgeSkuList
    from ._models_py3 import EdgeProfile
    from ._models_py3 import EdgeProfilePatch
    from ._models_py3 import EdgeProfileSubscription
    from ._models_py3 import EdgeProfileSubscriptionPatch
    from ._models_py3 import EtcdInfo
    from ._models_py3 import FileEventTrigger
    from ._models_py3 import FileSourceInfo
    from ._models_py3 import GenerateCertResponse
    from ._models_py3 import ImageRepositoryCredential
    from ._models_py3 import IoTAddon
    from ._models_py3 import IoTDeviceInfo
    from ._models_py3 import IoTEdgeAgentInfo
    from ._models_py3 import IoTRole
    from ._models_py3 import Ipv4Config
    from ._models_py3 import Ipv6Config
    from ._models_py3 import Job
    from ._models_py3 import JobErrorDetails
    from ._models_py3 import JobErrorItem
    from ._models_py3 import KubernetesClusterInfo
    from ._models_py3 import KubernetesIPConfiguration
    from ._models_py3 import KubernetesRole
    from ._models_py3 import KubernetesRoleCompute
    from ._models_py3 import KubernetesRoleNetwork
    from ._models_py3 import KubernetesRoleResources
    from ._models_py3 import KubernetesRoleStorage
    from ._models_py3 import KubernetesRoleStorageClassInfo
    from ._models_py3 import LoadBalancerConfig
    from ._models_py3 import MECRole
    from ._models_py3 import MetricConfiguration
    from ._models_py3 import MetricCounter
    from ._models_py3 import MetricCounterSet
    from ._models_py3 import MetricDimension
    from ._models_py3 import MetricDimensionV1
    from ._models_py3 import MetricSpecificationV1
    from ._models_py3 import MonitoringMetricConfiguration
    from ._models_py3 import MonitoringMetricConfigurationList
    from ._models_py3 import MountPointMap
    from ._models_py3 import NetworkAdapter
    from ._models_py3 import NetworkAdapterPosition
    from ._models_py3 import NetworkSettings
    from ._models_py3 import Node
    from ._models_py3 import NodeInfo
    from ._models_py3 import NodeList
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationsList
    from ._models_py3 import Order
    from ._models_py3 import OrderList
    from ._models_py3 import OrderStatus
    from ._models_py3 import PeriodicTimerEventTrigger
    from ._models_py3 import PeriodicTimerSourceInfo
    from ._models_py3 import RefreshDetails
    from ._models_py3 import ResourceIdentity
    from ._models_py3 import ResourceMoveDetails
    from ._models_py3 import ResourceTypeSku
    from ._models_py3 import Role
    from ._models_py3 import RoleList
    from ._models_py3 import RoleSinkInfo
    from ._models_py3 import SecuritySettings
    from ._models_py3 import ServiceSpecification
    from ._models_py3 import Share
    from ._models_py3 import ShareAccessRight
    from ._models_py3 import ShareList
    from ._models_py3 import Sku
    from ._models_py3 import SkuCost
    from ._models_py3 import SkuInformation
    from ._models_py3 import SkuInformationList
    from ._models_py3 import SkuLocationInfo
    from ._models_py3 import StorageAccount
    from ._models_py3 import StorageAccountCredential
    from ._models_py3 import StorageAccountCredentialList
    from ._models_py3 import StorageAccountList
    from ._models_py3 import SubscriptionRegisteredFeatures
    from ._models_py3 import SymmetricKey
    from ._models_py3 import SystemData
    from ._models_py3 import TrackingInfo
    from ._models_py3 import Trigger
    from ._models_py3 import TriggerList
    from ._models_py3 import UpdateDownloadProgress
    from ._models_py3 import UpdateInstallProgress
    from ._models_py3 import UpdateSummary
    from ._models_py3 import UploadCertificateRequest
    from ._models_py3 import UploadCertificateResponse
    from ._models_py3 import User
    from ._models_py3 import UserAccessRight
    from ._models_py3 import UserList
except (SyntaxError, ImportError):
    from ._models import ARMBaseModel  # type: ignore
    from ._models import Addon  # type: ignore
    from ._models import AddonList  # type: ignore
    from ._models import Address  # type: ignore
    from ._models import Alert  # type: ignore
    from ._models import AlertErrorDetails  # type: ignore
    from ._models import AlertList  # type: ignore
    from ._models import ArcAddon  # type: ignore
    from ._models import AsymmetricEncryptedSecret  # type: ignore
    from ._models import Authentication  # type: ignore
    from ._models import AzureContainerInfo  # type: ignore
    from ._models import BandwidthSchedule  # type: ignore
    from ._models import BandwidthSchedulesList  # type: ignore
    from ._models import ClientAccessRight  # type: ignore
    from ._models import CloudEdgeManagementRole  # type: ignore
    from ._models import CloudErrorBody  # type: ignore
    from ._models import CniConfig  # type: ignore
    from ._models import ComputeResource  # type: ignore
    from ._models import ContactDetails  # type: ignore
    from ._models import Container  # type: ignore
    from ._models import ContainerList  # type: ignore
    from ._models import DCAccessCode  # type: ignore
    from ._models import DataBoxEdgeDevice  # type: ignore
    from ._models import DataBoxEdgeDeviceExtendedInfo  # type: ignore
    from ._models import DataBoxEdgeDeviceExtendedInfoPatch  # type: ignore
    from ._models import DataBoxEdgeDeviceList  # type: ignore
    from ._models import DataBoxEdgeDevicePatch  # type: ignore
    from ._models import DataBoxEdgeMoveRequest  # type: ignore
    from ._models import DataBoxEdgeSku  # type: ignore
    from ._models import DataBoxEdgeSkuList  # type: ignore
    from ._models import EdgeProfile  # type: ignore
    from ._models import EdgeProfilePatch  # type: ignore
    from ._models import EdgeProfileSubscription  # type: ignore
    from ._models import EdgeProfileSubscriptionPatch  # type: ignore
    from ._models import EtcdInfo  # type: ignore
    from ._models import FileEventTrigger  # type: ignore
    from ._models import FileSourceInfo  # type: ignore
    from ._models import GenerateCertResponse  # type: ignore
    from ._models import ImageRepositoryCredential  # type: ignore
    from ._models import IoTAddon  # type: ignore
    from ._models import IoTDeviceInfo  # type: ignore
    from ._models import IoTEdgeAgentInfo  # type: ignore
    from ._models import IoTRole  # type: ignore
    from ._models import Ipv4Config  # type: ignore
    from ._models import Ipv6Config  # type: ignore
    from ._models import Job  # type: ignore
    from ._models import JobErrorDetails  # type: ignore
    from ._models import JobErrorItem  # type: ignore
    from ._models import KubernetesClusterInfo  # type: ignore
    from ._models import KubernetesIPConfiguration  # type: ignore
    from ._models import KubernetesRole  # type: ignore
    from ._models import KubernetesRoleCompute  # type: ignore
    from ._models import KubernetesRoleNetwork  # type: ignore
    from ._models import KubernetesRoleResources  # type: ignore
    from ._models import KubernetesRoleStorage  # type: ignore
    from ._models import KubernetesRoleStorageClassInfo  # type: ignore
    from ._models import LoadBalancerConfig  # type: ignore
    from ._models import MECRole  # type: ignore
    from ._models import MetricConfiguration  # type: ignore
    from ._models import MetricCounter  # type: ignore
    from ._models import MetricCounterSet  # type: ignore
    from ._models import MetricDimension  # type: ignore
    from ._models import MetricDimensionV1  # type: ignore
    from ._models import MetricSpecificationV1  # type: ignore
    from ._models import MonitoringMetricConfiguration  # type: ignore
    from ._models import MonitoringMetricConfigurationList  # type: ignore
    from ._models import MountPointMap  # type: ignore
    from ._models import NetworkAdapter  # type: ignore
    from ._models import NetworkAdapterPosition  # type: ignore
    from ._models import NetworkSettings  # type: ignore
    from ._models import Node  # type: ignore
    from ._models import NodeInfo  # type: ignore
    from ._models import NodeList  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationDisplay  # type: ignore
    from ._models import OperationsList  # type: ignore
    from ._models import Order  # type: ignore
    from ._models import OrderList  # type: ignore
    from ._models import OrderStatus  # type: ignore
    from ._models import PeriodicTimerEventTrigger  # type: ignore
    from ._models import PeriodicTimerSourceInfo  # type: ignore
    from ._models import RefreshDetails  # type: ignore
    from ._models import ResourceIdentity  # type: ignore
    from ._models import ResourceMoveDetails  # type: ignore
    from ._models import ResourceTypeSku  # type: ignore
    from ._models import Role  # type: ignore
    from ._models import RoleList  # type: ignore
    from ._models import RoleSinkInfo  # type: ignore
    from ._models import SecuritySettings  # type: ignore
    from ._models import ServiceSpecification  # type: ignore
    from ._models import Share  # type: ignore
    from ._models import ShareAccessRight  # type: ignore
    from ._models import ShareList  # type: ignore
    from ._models import Sku  # type: ignore
    from ._models import SkuCost  # type: ignore
    from ._models import SkuInformation  # type: ignore
    from ._models import SkuInformationList  # type: ignore
    from ._models import SkuLocationInfo  # type: ignore
    from ._models import StorageAccount  # type: ignore
    from ._models import StorageAccountCredential  # type: ignore
    from ._models import StorageAccountCredentialList  # type: ignore
    from ._models import StorageAccountList  # type: ignore
    from ._models import SubscriptionRegisteredFeatures  # type: ignore
    from ._models import SymmetricKey  # type: ignore
    from ._models import SystemData  # type: ignore
    from ._models import TrackingInfo  # type: ignore
    from ._models import Trigger  # type: ignore
    from ._models import TriggerList  # type: ignore
    from ._models import UpdateDownloadProgress  # type: ignore
    from ._models import UpdateInstallProgress  # type: ignore
    from ._models import UpdateSummary  # type: ignore
    from ._models import UploadCertificateRequest  # type: ignore
    from ._models import UploadCertificateResponse  # type: ignore
    from ._models import User  # type: ignore
    from ._models import UserAccessRight  # type: ignore
    from ._models import UserList  # type: ignore

from ._data_box_edge_management_client_enums import (
    AccountType,
    AddonState,
    AddonType,
    AlertSeverity,
    AuthenticationType,
    AzureContainerDataFormat,
    ClientPermissionType,
    ContainerStatus,
    CreatedByType,
    DataBoxEdgeDeviceKind,
    DataBoxEdgeDeviceStatus,
    DataPolicy,
    DayOfWeek,
    DeviceType,
    DownloadPhase,
    EncryptionAlgorithm,
    HostPlatformType,
    InstallRebootBehavior,
    JobStatus,
    JobType,
    KubernetesNodeType,
    KubernetesState,
    MetricAggregationType,
    MetricCategory,
    MetricUnit,
    MonitoringStatus,
    MountType,
    MsiIdentityType,
    NetworkAdapterDHCPStatus,
    NetworkAdapterRDMAStatus,
    NetworkAdapterStatus,
    NetworkGroup,
    NodeStatus,
    OrderState,
    PlatformType,
    PosixComplianceStatus,
    ResourceMoveStatus,
    RoleStatus,
    RoleTypes,
    SSLStatus,
    ShareAccessProtocol,
    ShareAccessType,
    ShareStatus,
    ShipmentType,
    SkuAvailability,
    SkuName,
    SkuSignupOption,
    SkuTier,
    SkuVersion,
    StorageAccountStatus,
    SubscriptionState,
    TimeGrain,
    TriggerEventType,
    UpdateOperation,
    UpdateOperationStage,
    UserType,
)

__all__ = [
    'ARMBaseModel',
    'Addon',
    'AddonList',
    'Address',
    'Alert',
    'AlertErrorDetails',
    'AlertList',
    'ArcAddon',
    'AsymmetricEncryptedSecret',
    'Authentication',
    'AzureContainerInfo',
    'BandwidthSchedule',
    'BandwidthSchedulesList',
    'ClientAccessRight',
    'CloudEdgeManagementRole',
    'CloudErrorBody',
    'CniConfig',
    'ComputeResource',
    'ContactDetails',
    'Container',
    'ContainerList',
    'DCAccessCode',
    'DataBoxEdgeDevice',
    'DataBoxEdgeDeviceExtendedInfo',
    'DataBoxEdgeDeviceExtendedInfoPatch',
    'DataBoxEdgeDeviceList',
    'DataBoxEdgeDevicePatch',
    'DataBoxEdgeMoveRequest',
    'DataBoxEdgeSku',
    'DataBoxEdgeSkuList',
    'EdgeProfile',
    'EdgeProfilePatch',
    'EdgeProfileSubscription',
    'EdgeProfileSubscriptionPatch',
    'EtcdInfo',
    'FileEventTrigger',
    'FileSourceInfo',
    'GenerateCertResponse',
    'ImageRepositoryCredential',
    'IoTAddon',
    'IoTDeviceInfo',
    'IoTEdgeAgentInfo',
    'IoTRole',
    'Ipv4Config',
    'Ipv6Config',
    'Job',
    'JobErrorDetails',
    'JobErrorItem',
    'KubernetesClusterInfo',
    'KubernetesIPConfiguration',
    'KubernetesRole',
    'KubernetesRoleCompute',
    'KubernetesRoleNetwork',
    'KubernetesRoleResources',
    'KubernetesRoleStorage',
    'KubernetesRoleStorageClassInfo',
    'LoadBalancerConfig',
    'MECRole',
    'MetricConfiguration',
    'MetricCounter',
    'MetricCounterSet',
    'MetricDimension',
    'MetricDimensionV1',
    'MetricSpecificationV1',
    'MonitoringMetricConfiguration',
    'MonitoringMetricConfigurationList',
    'MountPointMap',
    'NetworkAdapter',
    'NetworkAdapterPosition',
    'NetworkSettings',
    'Node',
    'NodeInfo',
    'NodeList',
    'Operation',
    'OperationDisplay',
    'OperationsList',
    'Order',
    'OrderList',
    'OrderStatus',
    'PeriodicTimerEventTrigger',
    'PeriodicTimerSourceInfo',
    'RefreshDetails',
    'ResourceIdentity',
    'ResourceMoveDetails',
    'ResourceTypeSku',
    'Role',
    'RoleList',
    'RoleSinkInfo',
    'SecuritySettings',
    'ServiceSpecification',
    'Share',
    'ShareAccessRight',
    'ShareList',
    'Sku',
    'SkuCost',
    'SkuInformation',
    'SkuInformationList',
    'SkuLocationInfo',
    'StorageAccount',
    'StorageAccountCredential',
    'StorageAccountCredentialList',
    'StorageAccountList',
    'SubscriptionRegisteredFeatures',
    'SymmetricKey',
    'SystemData',
    'TrackingInfo',
    'Trigger',
    'TriggerList',
    'UpdateDownloadProgress',
    'UpdateInstallProgress',
    'UpdateSummary',
    'UploadCertificateRequest',
    'UploadCertificateResponse',
    'User',
    'UserAccessRight',
    'UserList',
    'AccountType',
    'AddonState',
    'AddonType',
    'AlertSeverity',
    'AuthenticationType',
    'AzureContainerDataFormat',
    'ClientPermissionType',
    'ContainerStatus',
    'CreatedByType',
    'DataBoxEdgeDeviceKind',
    'DataBoxEdgeDeviceStatus',
    'DataPolicy',
    'DayOfWeek',
    'DeviceType',
    'DownloadPhase',
    'EncryptionAlgorithm',
    'HostPlatformType',
    'InstallRebootBehavior',
    'JobStatus',
    'JobType',
    'KubernetesNodeType',
    'KubernetesState',
    'MetricAggregationType',
    'MetricCategory',
    'MetricUnit',
    'MonitoringStatus',
    'MountType',
    'MsiIdentityType',
    'NetworkAdapterDHCPStatus',
    'NetworkAdapterRDMAStatus',
    'NetworkAdapterStatus',
    'NetworkGroup',
    'NodeStatus',
    'OrderState',
    'PlatformType',
    'PosixComplianceStatus',
    'ResourceMoveStatus',
    'RoleStatus',
    'RoleTypes',
    'SSLStatus',
    'ShareAccessProtocol',
    'ShareAccessType',
    'ShareStatus',
    'ShipmentType',
    'SkuAvailability',
    'SkuName',
    'SkuSignupOption',
    'SkuTier',
    'SkuVersion',
    'StorageAccountStatus',
    'SubscriptionState',
    'TimeGrain',
    'TriggerEventType',
    'UpdateOperation',
    'UpdateOperationStage',
    'UserType',
]
