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
    from ._models_py3 import AffectedMoveResource
    from ._models_py3 import AutomaticResolutionProperties
    from ._models_py3 import AvailabilitySetResourceSettings
    from ._models_py3 import AzureResourceReference
    from ._models_py3 import CommitRequest
    from ._models_py3 import DiscardRequest
    from ._models_py3 import Display
    from ._models_py3 import Identity
    from ._models_py3 import JobStatus
    from ._models_py3 import LBBackendAddressPoolResourceSettings
    from ._models_py3 import LBFrontendIPConfigurationResourceSettings
    from ._models_py3 import LoadBalancerBackendAddressPoolReference
    from ._models_py3 import LoadBalancerNatRuleReference
    from ._models_py3 import LoadBalancerResourceSettings
    from ._models_py3 import ManualResolutionProperties
    from ._models_py3 import MoveCollection
    from ._models_py3 import MoveCollectionProperties
    from ._models_py3 import MoveErrorInfo
    from ._models_py3 import MoveResource
    from ._models_py3 import MoveResourceDependency
    from ._models_py3 import MoveResourceDependencyOverride
    from ._models_py3 import MoveResourceError
    from ._models_py3 import MoveResourceErrorBody
    from ._models_py3 import MoveResourceFilter
    from ._models_py3 import MoveResourceFilterProperties
    from ._models_py3 import MoveResourceProperties
    from ._models_py3 import MoveResourcePropertiesMoveStatus
    from ._models_py3 import MoveResourcePropertiesSourceResourceSettings
    from ._models_py3 import MoveResourceStatus
    from ._models_py3 import NetworkInterfaceResourceSettings
    from ._models_py3 import NetworkSecurityGroupResourceSettings
    from ._models_py3 import NicIpConfigurationResourceSettings
    from ._models_py3 import NsgSecurityRule
    from ._models_py3 import OperationErrorAdditionalInfo
    from ._models_py3 import OperationsDiscovery
    from ._models_py3 import OperationsDiscoveryCollection
    from ._models_py3 import OperationStatus
    from ._models_py3 import OperationStatusError
    from ._models_py3 import PrepareRequest
    from ._models_py3 import ProxyResourceReference
    from ._models_py3 import PublicIPAddressResourceSettings
    from ._models_py3 import ResourceGroupResourceSettings
    from ._models_py3 import ResourceMoveRequest
    from ._models_py3 import ResourceSettings
    from ._models_py3 import SqlDatabaseResourceSettings
    from ._models_py3 import SqlElasticPoolResourceSettings
    from ._models_py3 import SqlServerResourceSettings
    from ._models_py3 import SubnetReference
    from ._models_py3 import SubnetResourceSettings
    from ._models_py3 import UnresolvedDependency
    from ._models_py3 import UnresolvedDependencyCollection
    from ._models_py3 import UpdateMoveCollectionRequest
    from ._models_py3 import VirtualMachineResourceSettings
    from ._models_py3 import VirtualNetworkResourceSettings
except (SyntaxError, ImportError):
    from ._models import AffectedMoveResource
    from ._models import AutomaticResolutionProperties
    from ._models import AvailabilitySetResourceSettings
    from ._models import AzureResourceReference
    from ._models import CommitRequest
    from ._models import DiscardRequest
    from ._models import Display
    from ._models import Identity
    from ._models import JobStatus
    from ._models import LBBackendAddressPoolResourceSettings
    from ._models import LBFrontendIPConfigurationResourceSettings
    from ._models import LoadBalancerBackendAddressPoolReference
    from ._models import LoadBalancerNatRuleReference
    from ._models import LoadBalancerResourceSettings
    from ._models import ManualResolutionProperties
    from ._models import MoveCollection
    from ._models import MoveCollectionProperties
    from ._models import MoveErrorInfo
    from ._models import MoveResource
    from ._models import MoveResourceDependency
    from ._models import MoveResourceDependencyOverride
    from ._models import MoveResourceError
    from ._models import MoveResourceErrorBody
    from ._models import MoveResourceFilter
    from ._models import MoveResourceFilterProperties
    from ._models import MoveResourceProperties
    from ._models import MoveResourcePropertiesMoveStatus
    from ._models import MoveResourcePropertiesSourceResourceSettings
    from ._models import MoveResourceStatus
    from ._models import NetworkInterfaceResourceSettings
    from ._models import NetworkSecurityGroupResourceSettings
    from ._models import NicIpConfigurationResourceSettings
    from ._models import NsgSecurityRule
    from ._models import OperationErrorAdditionalInfo
    from ._models import OperationsDiscovery
    from ._models import OperationsDiscoveryCollection
    from ._models import OperationStatus
    from ._models import OperationStatusError
    from ._models import PrepareRequest
    from ._models import ProxyResourceReference
    from ._models import PublicIPAddressResourceSettings
    from ._models import ResourceGroupResourceSettings
    from ._models import ResourceMoveRequest
    from ._models import ResourceSettings
    from ._models import SqlDatabaseResourceSettings
    from ._models import SqlElasticPoolResourceSettings
    from ._models import SqlServerResourceSettings
    from ._models import SubnetReference
    from ._models import SubnetResourceSettings
    from ._models import UnresolvedDependency
    from ._models import UnresolvedDependencyCollection
    from ._models import UpdateMoveCollectionRequest
    from ._models import VirtualMachineResourceSettings
    from ._models import VirtualNetworkResourceSettings
from ._paged_models import MoveCollectionPaged
from ._paged_models import MoveResourcePaged
from ._region_move_service_api_enums import (
    ResourceIdentityType,
    MoveState,
    MoveResourceInputType,
    ProvisioningState,
    JobName,
    ResolutionType,
    DependencyType,
    TargetAvailabilityZone,
    ZoneRedundant,
)

__all__ = [
    'AffectedMoveResource',
    'AutomaticResolutionProperties',
    'AvailabilitySetResourceSettings',
    'AzureResourceReference',
    'CommitRequest',
    'DiscardRequest',
    'Display',
    'Identity',
    'JobStatus',
    'LBBackendAddressPoolResourceSettings',
    'LBFrontendIPConfigurationResourceSettings',
    'LoadBalancerBackendAddressPoolReference',
    'LoadBalancerNatRuleReference',
    'LoadBalancerResourceSettings',
    'ManualResolutionProperties',
    'MoveCollection',
    'MoveCollectionProperties',
    'MoveErrorInfo',
    'MoveResource',
    'MoveResourceDependency',
    'MoveResourceDependencyOverride',
    'MoveResourceError',
    'MoveResourceErrorBody',
    'MoveResourceFilter',
    'MoveResourceFilterProperties',
    'MoveResourceProperties',
    'MoveResourcePropertiesMoveStatus',
    'MoveResourcePropertiesSourceResourceSettings',
    'MoveResourceStatus',
    'NetworkInterfaceResourceSettings',
    'NetworkSecurityGroupResourceSettings',
    'NicIpConfigurationResourceSettings',
    'NsgSecurityRule',
    'OperationErrorAdditionalInfo',
    'OperationsDiscovery',
    'OperationsDiscoveryCollection',
    'OperationStatus',
    'OperationStatusError',
    'PrepareRequest',
    'ProxyResourceReference',
    'PublicIPAddressResourceSettings',
    'ResourceGroupResourceSettings',
    'ResourceMoveRequest',
    'ResourceSettings',
    'SqlDatabaseResourceSettings',
    'SqlElasticPoolResourceSettings',
    'SqlServerResourceSettings',
    'SubnetReference',
    'SubnetResourceSettings',
    'UnresolvedDependency',
    'UnresolvedDependencyCollection',
    'UpdateMoveCollectionRequest',
    'VirtualMachineResourceSettings',
    'VirtualNetworkResourceSettings',
    'MoveCollectionPaged',
    'MoveResourcePaged',
    'ResourceIdentityType',
    'MoveState',
    'MoveResourceInputType',
    'ProvisioningState',
    'JobName',
    'ResolutionType',
    'DependencyType',
    'TargetAvailabilityZone',
    'ZoneRedundant',
]
