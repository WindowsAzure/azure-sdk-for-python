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
    from ._models_py3 import AzureFileVolume
    from ._models_py3 import CachedImages
    from ._models_py3 import Capabilities
    from ._models_py3 import CapabilitiesCapabilities
    from ._models_py3 import Container
    from ._models_py3 import ContainerExec
    from ._models_py3 import ContainerExecRequest
    from ._models_py3 import ContainerExecRequestTerminalSize
    from ._models_py3 import ContainerExecResponse
    from ._models_py3 import ContainerGroup
    from ._models_py3 import ContainerGroupDiagnostics
    from ._models_py3 import ContainerGroupIdentity
    from ._models_py3 import ContainerGroupIdentityUserAssignedIdentitiesValue
    from ._models_py3 import ContainerGroupNetworkProfile
    from ._models_py3 import ContainerGroupPropertiesInstanceView
    from ._models_py3 import ContainerHttpGet
    from ._models_py3 import ContainerPort
    from ._models_py3 import ContainerProbe
    from ._models_py3 import ContainerPropertiesInstanceView
    from ._models_py3 import ContainerState
    from ._models_py3 import DnsConfiguration
    from ._models_py3 import EncryptionProperties
    from ._models_py3 import EnvironmentVariable
    from ._models_py3 import Event
    from ._models_py3 import GitRepoVolume
    from ._models_py3 import GpuResource
    from ._models_py3 import ImageRegistryCredential
    from ._models_py3 import InitContainerDefinition
    from ._models_py3 import InitContainerPropertiesDefinitionInstanceView
    from ._models_py3 import IpAddress
    from ._models_py3 import LogAnalytics
    from ._models_py3 import Logs
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import Port
    from ._models_py3 import Resource
    from ._models_py3 import ResourceLimits
    from ._models_py3 import ResourceRequests
    from ._models_py3 import ResourceRequirements
    from ._models_py3 import Usage
    from ._models_py3 import UsageName
    from ._models_py3 import Volume
    from ._models_py3 import VolumeMount
except (SyntaxError, ImportError):
    from ._models import AzureFileVolume
    from ._models import CachedImages
    from ._models import Capabilities
    from ._models import CapabilitiesCapabilities
    from ._models import Container
    from ._models import ContainerExec
    from ._models import ContainerExecRequest
    from ._models import ContainerExecRequestTerminalSize
    from ._models import ContainerExecResponse
    from ._models import ContainerGroup
    from ._models import ContainerGroupDiagnostics
    from ._models import ContainerGroupIdentity
    from ._models import ContainerGroupIdentityUserAssignedIdentitiesValue
    from ._models import ContainerGroupNetworkProfile
    from ._models import ContainerGroupPropertiesInstanceView
    from ._models import ContainerHttpGet
    from ._models import ContainerPort
    from ._models import ContainerProbe
    from ._models import ContainerPropertiesInstanceView
    from ._models import ContainerState
    from ._models import DnsConfiguration
    from ._models import EncryptionProperties
    from ._models import EnvironmentVariable
    from ._models import Event
    from ._models import GitRepoVolume
    from ._models import GpuResource
    from ._models import ImageRegistryCredential
    from ._models import InitContainerDefinition
    from ._models import InitContainerPropertiesDefinitionInstanceView
    from ._models import IpAddress
    from ._models import LogAnalytics
    from ._models import Logs
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import Port
    from ._models import Resource
    from ._models import ResourceLimits
    from ._models import ResourceRequests
    from ._models import ResourceRequirements
    from ._models import Usage
    from ._models import UsageName
    from ._models import Volume
    from ._models import VolumeMount
from ._paged_models import CachedImagesPaged
from ._paged_models import CapabilitiesPaged
from ._paged_models import ContainerGroupPaged
from ._paged_models import OperationPaged
from ._paged_models import UsagePaged
from ._container_instance_management_client_enums import (
    ContainerNetworkProtocol,
    GpuSku,
    Scheme,
    ResourceIdentityType,
    ContainerGroupRestartPolicy,
    ContainerGroupNetworkProtocol,
    ContainerGroupIpAddressType,
    OperatingSystemTypes,
    LogAnalyticsLogType,
    ContainerGroupSku,
    ContainerInstanceOperationsOrigin,
)

__all__ = [
    'AzureFileVolume',
    'CachedImages',
    'Capabilities',
    'CapabilitiesCapabilities',
    'Container',
    'ContainerExec',
    'ContainerExecRequest',
    'ContainerExecRequestTerminalSize',
    'ContainerExecResponse',
    'ContainerGroup',
    'ContainerGroupDiagnostics',
    'ContainerGroupIdentity',
    'ContainerGroupIdentityUserAssignedIdentitiesValue',
    'ContainerGroupNetworkProfile',
    'ContainerGroupPropertiesInstanceView',
    'ContainerHttpGet',
    'ContainerPort',
    'ContainerProbe',
    'ContainerPropertiesInstanceView',
    'ContainerState',
    'DnsConfiguration',
    'EncryptionProperties',
    'EnvironmentVariable',
    'Event',
    'GitRepoVolume',
    'GpuResource',
    'ImageRegistryCredential',
    'InitContainerDefinition',
    'InitContainerPropertiesDefinitionInstanceView',
    'IpAddress',
    'LogAnalytics',
    'Logs',
    'Operation',
    'OperationDisplay',
    'Port',
    'Resource',
    'ResourceLimits',
    'ResourceRequests',
    'ResourceRequirements',
    'Usage',
    'UsageName',
    'Volume',
    'VolumeMount',
    'ContainerGroupPaged',
    'OperationPaged',
    'UsagePaged',
    'CachedImagesPaged',
    'CapabilitiesPaged',
    'ContainerNetworkProtocol',
    'GpuSku',
    'Scheme',
    'ResourceIdentityType',
    'ContainerGroupRestartPolicy',
    'ContainerGroupNetworkProtocol',
    'ContainerGroupIpAddressType',
    'OperatingSystemTypes',
    'LogAnalyticsLogType',
    'ContainerGroupSku',
    'ContainerInstanceOperationsOrigin',
]
