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
    from .address_py3 import Address
    from .alert_error_details_py3 import AlertErrorDetails
    from .alert_py3 import Alert
    from .arm_base_model_py3 import ARMBaseModel
    from .asymmetric_encrypted_secret_py3 import AsymmetricEncryptedSecret
    from .symmetric_key_py3 import SymmetricKey
    from .authentication_py3 import Authentication
    from .azure_container_info_py3 import AzureContainerInfo
    from .bandwidth_schedule_py3 import BandwidthSchedule
    from .client_access_right_py3 import ClientAccessRight
    from .contact_details_py3 import ContactDetails
    from .sku_py3 import Sku
    from .data_box_edge_device_py3 import DataBoxEdgeDevice
    from .data_box_edge_device_extended_info_py3 import DataBoxEdgeDeviceExtendedInfo
    from .data_box_edge_device_patch_py3 import DataBoxEdgeDevicePatch
    from .file_source_info_py3 import FileSourceInfo
    from .role_sink_info_py3 import RoleSinkInfo
    from .file_event_trigger_py3 import FileEventTrigger
    from .io_tdevice_info_py3 import IoTDeviceInfo
    from .mount_point_map_py3 import MountPointMap
    from .io_trole_py3 import IoTRole
    from .ipv4_config_py3 import Ipv4Config
    from .ipv6_config_py3 import Ipv6Config
    from .job_error_item_py3 import JobErrorItem
    from .job_error_details_py3 import JobErrorDetails
    from .update_download_progress_py3 import UpdateDownloadProgress
    from .update_install_progress_py3 import UpdateInstallProgress
    from .job_py3 import Job
    from .metric_dimension_v1_py3 import MetricDimensionV1
    from .metric_specification_v1_py3 import MetricSpecificationV1
    from .network_adapter_position_py3 import NetworkAdapterPosition
    from .network_adapter_py3 import NetworkAdapter
    from .network_settings_py3 import NetworkSettings
    from .operation_display_py3 import OperationDisplay
    from .service_specification_py3 import ServiceSpecification
    from .operation_py3 import Operation
    from .order_status_py3 import OrderStatus
    from .tracking_info_py3 import TrackingInfo
    from .order_py3 import Order
    from .periodic_timer_source_info_py3 import PeriodicTimerSourceInfo
    from .periodic_timer_event_trigger_py3 import PeriodicTimerEventTrigger
    from .refresh_details_py3 import RefreshDetails
    from .role_py3 import Role
    from .security_settings_py3 import SecuritySettings
    from .user_access_right_py3 import UserAccessRight
    from .share_py3 import Share
    from .share_access_right_py3 import ShareAccessRight
    from .storage_account_credential_py3 import StorageAccountCredential
    from .trigger_py3 import Trigger
    from .update_summary_py3 import UpdateSummary
    from .upload_certificate_request_py3 import UploadCertificateRequest
    from .upload_certificate_response_py3 import UploadCertificateResponse
    from .user_py3 import User
except (SyntaxError, ImportError):
    from .address import Address
    from .alert_error_details import AlertErrorDetails
    from .alert import Alert
    from .arm_base_model import ARMBaseModel
    from .asymmetric_encrypted_secret import AsymmetricEncryptedSecret
    from .symmetric_key import SymmetricKey
    from .authentication import Authentication
    from .azure_container_info import AzureContainerInfo
    from .bandwidth_schedule import BandwidthSchedule
    from .client_access_right import ClientAccessRight
    from .contact_details import ContactDetails
    from .sku import Sku
    from .data_box_edge_device import DataBoxEdgeDevice
    from .data_box_edge_device_extended_info import DataBoxEdgeDeviceExtendedInfo
    from .data_box_edge_device_patch import DataBoxEdgeDevicePatch
    from .file_source_info import FileSourceInfo
    from .role_sink_info import RoleSinkInfo
    from .file_event_trigger import FileEventTrigger
    from .io_tdevice_info import IoTDeviceInfo
    from .mount_point_map import MountPointMap
    from .io_trole import IoTRole
    from .ipv4_config import Ipv4Config
    from .ipv6_config import Ipv6Config
    from .job_error_item import JobErrorItem
    from .job_error_details import JobErrorDetails
    from .update_download_progress import UpdateDownloadProgress
    from .update_install_progress import UpdateInstallProgress
    from .job import Job
    from .metric_dimension_v1 import MetricDimensionV1
    from .metric_specification_v1 import MetricSpecificationV1
    from .network_adapter_position import NetworkAdapterPosition
    from .network_adapter import NetworkAdapter
    from .network_settings import NetworkSettings
    from .operation_display import OperationDisplay
    from .service_specification import ServiceSpecification
    from .operation import Operation
    from .order_status import OrderStatus
    from .tracking_info import TrackingInfo
    from .order import Order
    from .periodic_timer_source_info import PeriodicTimerSourceInfo
    from .periodic_timer_event_trigger import PeriodicTimerEventTrigger
    from .refresh_details import RefreshDetails
    from .role import Role
    from .security_settings import SecuritySettings
    from .user_access_right import UserAccessRight
    from .share import Share
    from .share_access_right import ShareAccessRight
    from .storage_account_credential import StorageAccountCredential
    from .trigger import Trigger
    from .update_summary import UpdateSummary
    from .upload_certificate_request import UploadCertificateRequest
    from .upload_certificate_response import UploadCertificateResponse
    from .user import User
from .operation_paged import OperationPaged
from .data_box_edge_device_paged import DataBoxEdgeDevicePaged
from .alert_paged import AlertPaged
from .bandwidth_schedule_paged import BandwidthSchedulePaged
from .order_paged import OrderPaged
from .role_paged import RolePaged
from .share_paged import SharePaged
from .storage_account_credential_paged import StorageAccountCredentialPaged
from .trigger_paged import TriggerPaged
from .user_paged import UserPaged
from .data_box_edge_management_client_enums import (
    AlertSeverity,
    EncryptionAlgorithm,
    AzureContainerDataFormat,
    DayOfWeek,
    ClientPermissionType,
    SkuName,
    SkuTier,
    DataBoxEdgeDeviceStatus,
    DeviceType,
    RoleTypes,
    PlatformType,
    RoleStatus,
    JobStatus,
    JobType,
    UpdateOperationStage,
    DownloadPhase,
    MetricUnit,
    MetricAggregationType,
    MetricCategory,
    TimeGrain,
    NetworkGroup,
    NetworkAdapterStatus,
    NetworkAdapterRDMAStatus,
    NetworkAdapterDHCPStatus,
    OrderState,
    AuthenticationType,
    ShareStatus,
    MonitoringStatus,
    ShareAccessProtocol,
    ShareAccessType,
    DataPolicy,
    SSLStatus,
    AccountType,
    InstallRebootBehavior,
    UpdateOperation,
)

__all__ = [
    'Address',
    'AlertErrorDetails',
    'Alert',
    'ARMBaseModel',
    'AsymmetricEncryptedSecret',
    'SymmetricKey',
    'Authentication',
    'AzureContainerInfo',
    'BandwidthSchedule',
    'ClientAccessRight',
    'ContactDetails',
    'Sku',
    'DataBoxEdgeDevice',
    'DataBoxEdgeDeviceExtendedInfo',
    'DataBoxEdgeDevicePatch',
    'FileSourceInfo',
    'RoleSinkInfo',
    'FileEventTrigger',
    'IoTDeviceInfo',
    'MountPointMap',
    'IoTRole',
    'Ipv4Config',
    'Ipv6Config',
    'JobErrorItem',
    'JobErrorDetails',
    'UpdateDownloadProgress',
    'UpdateInstallProgress',
    'Job',
    'MetricDimensionV1',
    'MetricSpecificationV1',
    'NetworkAdapterPosition',
    'NetworkAdapter',
    'NetworkSettings',
    'OperationDisplay',
    'ServiceSpecification',
    'Operation',
    'OrderStatus',
    'TrackingInfo',
    'Order',
    'PeriodicTimerSourceInfo',
    'PeriodicTimerEventTrigger',
    'RefreshDetails',
    'Role',
    'SecuritySettings',
    'UserAccessRight',
    'Share',
    'ShareAccessRight',
    'StorageAccountCredential',
    'Trigger',
    'UpdateSummary',
    'UploadCertificateRequest',
    'UploadCertificateResponse',
    'User',
    'OperationPaged',
    'DataBoxEdgeDevicePaged',
    'AlertPaged',
    'BandwidthSchedulePaged',
    'OrderPaged',
    'RolePaged',
    'SharePaged',
    'StorageAccountCredentialPaged',
    'TriggerPaged',
    'UserPaged',
    'AlertSeverity',
    'EncryptionAlgorithm',
    'AzureContainerDataFormat',
    'DayOfWeek',
    'ClientPermissionType',
    'SkuName',
    'SkuTier',
    'DataBoxEdgeDeviceStatus',
    'DeviceType',
    'RoleTypes',
    'PlatformType',
    'RoleStatus',
    'JobStatus',
    'JobType',
    'UpdateOperationStage',
    'DownloadPhase',
    'MetricUnit',
    'MetricAggregationType',
    'MetricCategory',
    'TimeGrain',
    'NetworkGroup',
    'NetworkAdapterStatus',
    'NetworkAdapterRDMAStatus',
    'NetworkAdapterDHCPStatus',
    'OrderState',
    'AuthenticationType',
    'ShareStatus',
    'MonitoringStatus',
    'ShareAccessProtocol',
    'ShareAccessType',
    'DataPolicy',
    'SSLStatus',
    'AccountType',
    'InstallRebootBehavior',
    'UpdateOperation',
]
