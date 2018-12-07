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
    from .private_ip_address_py3 import PrivateIPAddress
    from .load_balancer_configuration_py3 import LoadBalancerConfiguration
    from .resource_py3 import Resource
    from .proxy_resource_py3 import ProxyResource
    from .availability_group_listener_py3 import AvailabilityGroupListener
    from .operation_display_py3 import OperationDisplay
    from .operation_py3 import Operation
    from .wsfc_domain_profile_py3 import WsfcDomainProfile
    from .tracked_resource_py3 import TrackedResource
    from .sql_virtual_machine_group_py3 import SqlVirtualMachineGroup
    from .sql_virtual_machine_group_update_py3 import SqlVirtualMachineGroupUpdate
    from .resource_identity_py3 import ResourceIdentity
    from .wsfc_domain_credentials_py3 import WsfcDomainCredentials
    from .auto_patching_settings_py3 import AutoPatchingSettings
    from .auto_backup_settings_py3 import AutoBackupSettings
    from .key_vault_credential_settings_py3 import KeyVaultCredentialSettings
    from .sql_connectivity_update_settings_py3 import SqlConnectivityUpdateSettings
    from .sql_workload_type_update_settings_py3 import SqlWorkloadTypeUpdateSettings
    from .sql_storage_update_settings_py3 import SqlStorageUpdateSettings
    from .additional_features_server_configurations_py3 import AdditionalFeaturesServerConfigurations
    from .server_configurations_management_settings_py3 import ServerConfigurationsManagementSettings
    from .sql_virtual_machine_py3 import SqlVirtualMachine
    from .sql_virtual_machine_update_py3 import SqlVirtualMachineUpdate
except (SyntaxError, ImportError):
    from .private_ip_address import PrivateIPAddress
    from .load_balancer_configuration import LoadBalancerConfiguration
    from .resource import Resource
    from .proxy_resource import ProxyResource
    from .availability_group_listener import AvailabilityGroupListener
    from .operation_display import OperationDisplay
    from .operation import Operation
    from .wsfc_domain_profile import WsfcDomainProfile
    from .tracked_resource import TrackedResource
    from .sql_virtual_machine_group import SqlVirtualMachineGroup
    from .sql_virtual_machine_group_update import SqlVirtualMachineGroupUpdate
    from .resource_identity import ResourceIdentity
    from .wsfc_domain_credentials import WsfcDomainCredentials
    from .auto_patching_settings import AutoPatchingSettings
    from .auto_backup_settings import AutoBackupSettings
    from .key_vault_credential_settings import KeyVaultCredentialSettings
    from .sql_connectivity_update_settings import SqlConnectivityUpdateSettings
    from .sql_workload_type_update_settings import SqlWorkloadTypeUpdateSettings
    from .sql_storage_update_settings import SqlStorageUpdateSettings
    from .additional_features_server_configurations import AdditionalFeaturesServerConfigurations
    from .server_configurations_management_settings import ServerConfigurationsManagementSettings
    from .sql_virtual_machine import SqlVirtualMachine
    from .sql_virtual_machine_update import SqlVirtualMachineUpdate
from .availability_group_listener_paged import AvailabilityGroupListenerPaged
from .operation_paged import OperationPaged
from .sql_virtual_machine_group_paged import SqlVirtualMachineGroupPaged
from .sql_virtual_machine_paged import SqlVirtualMachinePaged
from .sql_virtual_machine_management_client_enums import (
    OperationOrigin,
    SqlImageSku,
    ScaleType,
    ClusterManagerType,
    ClusterConfiguration,
    IdentityType,
    SqlServerLicenseType,
    DayOfWeek,
    BackupScheduleType,
    FullBackupFrequencyType,
    ConnectivityType,
    SqlWorkloadType,
    DiskConfigurationType,
)

__all__ = [
    'PrivateIPAddress',
    'LoadBalancerConfiguration',
    'Resource',
    'ProxyResource',
    'AvailabilityGroupListener',
    'OperationDisplay',
    'Operation',
    'WsfcDomainProfile',
    'TrackedResource',
    'SqlVirtualMachineGroup',
    'SqlVirtualMachineGroupUpdate',
    'ResourceIdentity',
    'WsfcDomainCredentials',
    'AutoPatchingSettings',
    'AutoBackupSettings',
    'KeyVaultCredentialSettings',
    'SqlConnectivityUpdateSettings',
    'SqlWorkloadTypeUpdateSettings',
    'SqlStorageUpdateSettings',
    'AdditionalFeaturesServerConfigurations',
    'ServerConfigurationsManagementSettings',
    'SqlVirtualMachine',
    'SqlVirtualMachineUpdate',
    'AvailabilityGroupListenerPaged',
    'OperationPaged',
    'SqlVirtualMachineGroupPaged',
    'SqlVirtualMachinePaged',
    'OperationOrigin',
    'SqlImageSku',
    'ScaleType',
    'ClusterManagerType',
    'ClusterConfiguration',
    'IdentityType',
    'SqlServerLicenseType',
    'DayOfWeek',
    'BackupScheduleType',
    'FullBackupFrequencyType',
    'ConnectivityType',
    'SqlWorkloadType',
    'DiskConfigurationType',
]
