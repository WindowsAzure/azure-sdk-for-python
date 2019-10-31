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
    from ._models_py3 import AvailableOperation
    from ._models_py3 import AvailableOperationDisplay
    from ._models_py3 import AvailableOperationDisplayPropertyServiceSpecificationMetricsItem
    from ._models_py3 import AvailableOperationDisplayPropertyServiceSpecificationMetricsList
    from ._models_py3 import CSRPError, CSRPErrorException
    from ._models_py3 import CSRPErrorBody
    from ._models_py3 import CustomizationHostName
    from ._models_py3 import CustomizationIdentity
    from ._models_py3 import CustomizationIdentityUserData
    from ._models_py3 import CustomizationIPAddress
    from ._models_py3 import CustomizationIPSettings
    from ._models_py3 import CustomizationNicSetting
    from ._models_py3 import CustomizationPolicy
    from ._models_py3 import CustomizationSpecification
    from ._models_py3 import DedicatedCloudNode
    from ._models_py3 import DedicatedCloudService
    from ._models_py3 import GuestOSCustomization
    from ._models_py3 import GuestOSNICCustomization
    from ._models_py3 import OperationError
    from ._models_py3 import OperationResource
    from ._models_py3 import PatchPayload
    from ._models_py3 import PrivateCloud
    from ._models_py3 import ResourcePool
    from ._models_py3 import Sku
    from ._models_py3 import SkuAvailability
    from ._models_py3 import Usage
    from ._models_py3 import UsageName
    from ._models_py3 import VirtualDisk
    from ._models_py3 import VirtualDiskController
    from ._models_py3 import VirtualMachine
    from ._models_py3 import VirtualMachineStopMode
    from ._models_py3 import VirtualMachineTemplate
    from ._models_py3 import VirtualNetwork
    from ._models_py3 import VirtualNic
except (SyntaxError, ImportError):
    from ._models import AvailableOperation
    from ._models import AvailableOperationDisplay
    from ._models import AvailableOperationDisplayPropertyServiceSpecificationMetricsItem
    from ._models import AvailableOperationDisplayPropertyServiceSpecificationMetricsList
    from ._models import CSRPError, CSRPErrorException
    from ._models import CSRPErrorBody
    from ._models import CustomizationHostName
    from ._models import CustomizationIdentity
    from ._models import CustomizationIdentityUserData
    from ._models import CustomizationIPAddress
    from ._models import CustomizationIPSettings
    from ._models import CustomizationNicSetting
    from ._models import CustomizationPolicy
    from ._models import CustomizationSpecification
    from ._models import DedicatedCloudNode
    from ._models import DedicatedCloudService
    from ._models import GuestOSCustomization
    from ._models import GuestOSNICCustomization
    from ._models import OperationError
    from ._models import OperationResource
    from ._models import PatchPayload
    from ._models import PrivateCloud
    from ._models import ResourcePool
    from ._models import Sku
    from ._models import SkuAvailability
    from ._models import Usage
    from ._models import UsageName
    from ._models import VirtualDisk
    from ._models import VirtualDiskController
    from ._models import VirtualMachine
    from ._models import VirtualMachineStopMode
    from ._models import VirtualMachineTemplate
    from ._models import VirtualNetwork
    from ._models import VirtualNic
from ._paged_models import AvailableOperationPaged
from ._paged_models import CustomizationPolicyPaged
from ._paged_models import DedicatedCloudNodePaged
from ._paged_models import DedicatedCloudServicePaged
from ._paged_models import PrivateCloudPaged
from ._paged_models import ResourcePoolPaged
from ._paged_models import SkuAvailabilityPaged
from ._paged_models import UsagePaged
from ._paged_models import VirtualMachinePaged
from ._paged_models import VirtualMachineTemplatePaged
from ._paged_models import VirtualNetworkPaged
from ._vmware_cloud_simple_client_enums import (
    OperationOrigin,
    AggregationType,
    NodeStatus,
    OnboardingStatus,
    DiskIndependenceMode,
    NICType,
    PrivateCloudResourceType,
    UsageCount,
    GuestOSType,
    VirtualMachineStatus,
    StopMode,
)

__all__ = [
    'AvailableOperation',
    'AvailableOperationDisplay',
    'AvailableOperationDisplayPropertyServiceSpecificationMetricsItem',
    'AvailableOperationDisplayPropertyServiceSpecificationMetricsList',
    'CSRPError', 'CSRPErrorException',
    'CSRPErrorBody',
    'CustomizationHostName',
    'CustomizationIdentity',
    'CustomizationIdentityUserData',
    'CustomizationIPAddress',
    'CustomizationIPSettings',
    'CustomizationNicSetting',
    'CustomizationPolicy',
    'CustomizationSpecification',
    'DedicatedCloudNode',
    'DedicatedCloudService',
    'GuestOSCustomization',
    'GuestOSNICCustomization',
    'OperationError',
    'OperationResource',
    'PatchPayload',
    'PrivateCloud',
    'ResourcePool',
    'Sku',
    'SkuAvailability',
    'Usage',
    'UsageName',
    'VirtualDisk',
    'VirtualDiskController',
    'VirtualMachine',
    'VirtualMachineStopMode',
    'VirtualMachineTemplate',
    'VirtualNetwork',
    'VirtualNic',
    'AvailableOperationPaged',
    'DedicatedCloudNodePaged',
    'DedicatedCloudServicePaged',
    'SkuAvailabilityPaged',
    'PrivateCloudPaged',
    'CustomizationPolicyPaged',
    'ResourcePoolPaged',
    'VirtualMachineTemplatePaged',
    'VirtualNetworkPaged',
    'UsagePaged',
    'VirtualMachinePaged',
    'OperationOrigin',
    'AggregationType',
    'NodeStatus',
    'OnboardingStatus',
    'DiskIndependenceMode',
    'NICType',
    'PrivateCloudResourceType',
    'UsageCount',
    'GuestOSType',
    'VirtualMachineStatus',
    'StopMode',
]
