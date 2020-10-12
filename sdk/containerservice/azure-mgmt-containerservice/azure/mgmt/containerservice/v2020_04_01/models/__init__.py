# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AgentPool
    from ._models_py3 import AgentPoolAvailableVersions
    from ._models_py3 import AgentPoolAvailableVersionsPropertiesAgentPoolVersionsItem
    from ._models_py3 import AgentPoolListResult
    from ._models_py3 import AgentPoolUpgradeProfile
    from ._models_py3 import AgentPoolUpgradeProfilePropertiesUpgradesItem
    from ._models_py3 import AgentPoolUpgradeSettings
    from ._models_py3 import CloudErrorBody
    from ._models_py3 import Components1Q1Og48SchemasManagedclusterAllof1
    from ._models_py3 import ComponentsQit0EtSchemasManagedclusterpropertiesPropertiesIdentityprofileAdditionalproperties
    from ._models_py3 import ContainerServiceDiagnosticsProfile
    from ._models_py3 import ContainerServiceLinuxProfile
    from ._models_py3 import ContainerServiceMasterProfile
    from ._models_py3 import ContainerServiceNetworkProfile
    from ._models_py3 import ContainerServiceSshConfiguration
    from ._models_py3 import ContainerServiceSshPublicKey
    from ._models_py3 import ContainerServiceVMDiagnostics
    from ._models_py3 import CredentialResult
    from ._models_py3 import CredentialResults
    from ._models_py3 import ManagedCluster
    from ._models_py3 import ManagedClusterAADProfile
    from ._models_py3 import ManagedClusterAPIServerAccessProfile
    from ._models_py3 import ManagedClusterAccessProfile
    from ._models_py3 import ManagedClusterAddonProfile
    from ._models_py3 import ManagedClusterAddonProfileIdentity
    from ._models_py3 import ManagedClusterAgentPoolProfile
    from ._models_py3 import ManagedClusterAgentPoolProfileProperties
    from ._models_py3 import ManagedClusterIdentity
    from ._models_py3 import ManagedClusterListResult
    from ._models_py3 import ManagedClusterLoadBalancerProfile
    from ._models_py3 import ManagedClusterLoadBalancerProfileManagedOutboundIPs
    from ._models_py3 import ManagedClusterLoadBalancerProfileOutboundIPPrefixes
    from ._models_py3 import ManagedClusterLoadBalancerProfileOutboundIPs
    from ._models_py3 import ManagedClusterPoolUpgradeProfile
    from ._models_py3 import ManagedClusterPoolUpgradeProfileUpgradesItem
    from ._models_py3 import ManagedClusterPropertiesAutoScalerProfile
    from ._models_py3 import ManagedClusterSKU
    from ._models_py3 import ManagedClusterServicePrincipalProfile
    from ._models_py3 import ManagedClusterUpgradeProfile
    from ._models_py3 import ManagedClusterWindowsProfile
    from ._models_py3 import OperationListResult
    from ._models_py3 import OperationValue
    from ._models_py3 import Resource
    from ._models_py3 import ResourceReference
    from ._models_py3 import SubResource
    from ._models_py3 import TagsObject
    from ._models_py3 import UserAssignedIdentity
except (SyntaxError, ImportError):
    from ._models import AgentPool  # type: ignore
    from ._models import AgentPoolAvailableVersions  # type: ignore
    from ._models import AgentPoolAvailableVersionsPropertiesAgentPoolVersionsItem  # type: ignore
    from ._models import AgentPoolListResult  # type: ignore
    from ._models import AgentPoolUpgradeProfile  # type: ignore
    from ._models import AgentPoolUpgradeProfilePropertiesUpgradesItem  # type: ignore
    from ._models import AgentPoolUpgradeSettings  # type: ignore
    from ._models import CloudErrorBody  # type: ignore
    from ._models import Components1Q1Og48SchemasManagedclusterAllof1  # type: ignore
    from ._models import ComponentsQit0EtSchemasManagedclusterpropertiesPropertiesIdentityprofileAdditionalproperties  # type: ignore
    from ._models import ContainerServiceDiagnosticsProfile  # type: ignore
    from ._models import ContainerServiceLinuxProfile  # type: ignore
    from ._models import ContainerServiceMasterProfile  # type: ignore
    from ._models import ContainerServiceNetworkProfile  # type: ignore
    from ._models import ContainerServiceSshConfiguration  # type: ignore
    from ._models import ContainerServiceSshPublicKey  # type: ignore
    from ._models import ContainerServiceVMDiagnostics  # type: ignore
    from ._models import CredentialResult  # type: ignore
    from ._models import CredentialResults  # type: ignore
    from ._models import ManagedCluster  # type: ignore
    from ._models import ManagedClusterAADProfile  # type: ignore
    from ._models import ManagedClusterAPIServerAccessProfile  # type: ignore
    from ._models import ManagedClusterAccessProfile  # type: ignore
    from ._models import ManagedClusterAddonProfile  # type: ignore
    from ._models import ManagedClusterAddonProfileIdentity  # type: ignore
    from ._models import ManagedClusterAgentPoolProfile  # type: ignore
    from ._models import ManagedClusterAgentPoolProfileProperties  # type: ignore
    from ._models import ManagedClusterIdentity  # type: ignore
    from ._models import ManagedClusterListResult  # type: ignore
    from ._models import ManagedClusterLoadBalancerProfile  # type: ignore
    from ._models import ManagedClusterLoadBalancerProfileManagedOutboundIPs  # type: ignore
    from ._models import ManagedClusterLoadBalancerProfileOutboundIPPrefixes  # type: ignore
    from ._models import ManagedClusterLoadBalancerProfileOutboundIPs  # type: ignore
    from ._models import ManagedClusterPoolUpgradeProfile  # type: ignore
    from ._models import ManagedClusterPoolUpgradeProfileUpgradesItem  # type: ignore
    from ._models import ManagedClusterPropertiesAutoScalerProfile  # type: ignore
    from ._models import ManagedClusterSKU  # type: ignore
    from ._models import ManagedClusterServicePrincipalProfile  # type: ignore
    from ._models import ManagedClusterUpgradeProfile  # type: ignore
    from ._models import ManagedClusterWindowsProfile  # type: ignore
    from ._models import OperationListResult  # type: ignore
    from ._models import OperationValue  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceReference  # type: ignore
    from ._models import SubResource  # type: ignore
    from ._models import TagsObject  # type: ignore
    from ._models import UserAssignedIdentity  # type: ignore

from ._container_service_client_enums import (
    AgentPoolMode,
    AgentPoolType,
    ContainerServiceStorageProfileTypes,
    ContainerServiceVMSizeTypes,
    Count,
    LoadBalancerSku,
    ManagedClusterSKUName,
    ManagedClusterSKUTier,
    NetworkMode,
    NetworkPlugin,
    NetworkPolicy,
    OSType,
    OutboundType,
    ResourceIdentityType,
    ScaleSetEvictionPolicy,
    ScaleSetPriority,
)

__all__ = [
    'AgentPool',
    'AgentPoolAvailableVersions',
    'AgentPoolAvailableVersionsPropertiesAgentPoolVersionsItem',
    'AgentPoolListResult',
    'AgentPoolUpgradeProfile',
    'AgentPoolUpgradeProfilePropertiesUpgradesItem',
    'AgentPoolUpgradeSettings',
    'CloudErrorBody',
    'Components1Q1Og48SchemasManagedclusterAllof1',
    'ComponentsQit0EtSchemasManagedclusterpropertiesPropertiesIdentityprofileAdditionalproperties',
    'ContainerServiceDiagnosticsProfile',
    'ContainerServiceLinuxProfile',
    'ContainerServiceMasterProfile',
    'ContainerServiceNetworkProfile',
    'ContainerServiceSshConfiguration',
    'ContainerServiceSshPublicKey',
    'ContainerServiceVMDiagnostics',
    'CredentialResult',
    'CredentialResults',
    'ManagedCluster',
    'ManagedClusterAADProfile',
    'ManagedClusterAPIServerAccessProfile',
    'ManagedClusterAccessProfile',
    'ManagedClusterAddonProfile',
    'ManagedClusterAddonProfileIdentity',
    'ManagedClusterAgentPoolProfile',
    'ManagedClusterAgentPoolProfileProperties',
    'ManagedClusterIdentity',
    'ManagedClusterListResult',
    'ManagedClusterLoadBalancerProfile',
    'ManagedClusterLoadBalancerProfileManagedOutboundIPs',
    'ManagedClusterLoadBalancerProfileOutboundIPPrefixes',
    'ManagedClusterLoadBalancerProfileOutboundIPs',
    'ManagedClusterPoolUpgradeProfile',
    'ManagedClusterPoolUpgradeProfileUpgradesItem',
    'ManagedClusterPropertiesAutoScalerProfile',
    'ManagedClusterSKU',
    'ManagedClusterServicePrincipalProfile',
    'ManagedClusterUpgradeProfile',
    'ManagedClusterWindowsProfile',
    'OperationListResult',
    'OperationValue',
    'Resource',
    'ResourceReference',
    'SubResource',
    'TagsObject',
    'UserAssignedIdentity',
    'AgentPoolMode',
    'AgentPoolType',
    'ContainerServiceStorageProfileTypes',
    'ContainerServiceVMSizeTypes',
    'Count',
    'LoadBalancerSku',
    'ManagedClusterSKUName',
    'ManagedClusterSKUTier',
    'NetworkMode',
    'NetworkPlugin',
    'NetworkPolicy',
    'OSType',
    'OutboundType',
    'ResourceIdentityType',
    'ScaleSetEvictionPolicy',
    'ScaleSetPriority',
]
