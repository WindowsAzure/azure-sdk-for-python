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
    from ._models_py3 import AzureEntityResource
    from ._models_py3 import ErrorDetails, ErrorDetailsException
    from ._models_py3 import ErrorDetailsInternal
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationResultsDescription
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateLinkResource
    from ._models_py3 import PrivateLinkResourceListResult
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import PrivateLinkServicesForEDMUploadDescription
    from ._models_py3 import PrivateLinkServicesForM365ComplianceCenterDescription
    from ._models_py3 import PrivateLinkServicesForM365SecurityCenterDescription
    from ._models_py3 import PrivateLinkServicesForO365ManagementActivityAPIDescription
    from ._models_py3 import PrivateLinkServicesForSCCPowershellDescription
    from ._models_py3 import ProxyResource
    from ._models_py3 import Resource
    from ._models_py3 import ServiceAccessPolicyEntry
    from ._models_py3 import ServiceAuthenticationConfigurationInfo
    from ._models_py3 import ServiceCorsConfigurationInfo
    from ._models_py3 import ServiceCosmosDbConfigurationInfo
    from ._models_py3 import ServiceExportConfigurationInfo
    from ._models_py3 import ServicesPatchDescription
    from ._models_py3 import ServicesProperties
    from ._models_py3 import ServicesResource
    from ._models_py3 import ServicesResourceIdentity
    from ._models_py3 import SystemData
    from ._models_py3 import TrackedResource
except (SyntaxError, ImportError):
    from ._models import AzureEntityResource
    from ._models import ErrorDetails, ErrorDetailsException
    from ._models import ErrorDetailsInternal
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import OperationResultsDescription
    from ._models import PrivateEndpoint
    from ._models import PrivateEndpointConnection
    from ._models import PrivateLinkResource
    from ._models import PrivateLinkResourceListResult
    from ._models import PrivateLinkServiceConnectionState
    from ._models import PrivateLinkServicesForEDMUploadDescription
    from ._models import PrivateLinkServicesForM365ComplianceCenterDescription
    from ._models import PrivateLinkServicesForM365SecurityCenterDescription
    from ._models import PrivateLinkServicesForO365ManagementActivityAPIDescription
    from ._models import PrivateLinkServicesForSCCPowershellDescription
    from ._models import ProxyResource
    from ._models import Resource
    from ._models import ServiceAccessPolicyEntry
    from ._models import ServiceAuthenticationConfigurationInfo
    from ._models import ServiceCorsConfigurationInfo
    from ._models import ServiceCosmosDbConfigurationInfo
    from ._models import ServiceExportConfigurationInfo
    from ._models import ServicesPatchDescription
    from ._models import ServicesProperties
    from ._models import ServicesResource
    from ._models import ServicesResourceIdentity
    from ._models import SystemData
    from ._models import TrackedResource
from ._paged_models import OperationPaged
from ._paged_models import PrivateEndpointConnectionPaged
from ._paged_models import PrivateLinkServicesForEDMUploadDescriptionPaged
from ._paged_models import PrivateLinkServicesForM365ComplianceCenterDescriptionPaged
from ._paged_models import PrivateLinkServicesForM365SecurityCenterDescriptionPaged
from ._paged_models import PrivateLinkServicesForO365ManagementActivityAPIDescriptionPaged
from ._paged_models import PrivateLinkServicesForSCCPowershellDescriptionPaged
from ._security_and_compliance_ap_is_enums import (
    ProvisioningState,
    CreatedByType,
    PrivateEndpointServiceConnectionStatus,
    PrivateEndpointConnectionProvisioningState,
    PublicNetworkAccess,
    Kind,
    ManagedServiceIdentityType,
    OperationResultStatus,
)

__all__ = [
    'AzureEntityResource',
    'ErrorDetails', 'ErrorDetailsException',
    'ErrorDetailsInternal',
    'Operation',
    'OperationDisplay',
    'OperationResultsDescription',
    'PrivateEndpoint',
    'PrivateEndpointConnection',
    'PrivateLinkResource',
    'PrivateLinkResourceListResult',
    'PrivateLinkServiceConnectionState',
    'PrivateLinkServicesForEDMUploadDescription',
    'PrivateLinkServicesForM365ComplianceCenterDescription',
    'PrivateLinkServicesForM365SecurityCenterDescription',
    'PrivateLinkServicesForO365ManagementActivityAPIDescription',
    'PrivateLinkServicesForSCCPowershellDescription',
    'ProxyResource',
    'Resource',
    'ServiceAccessPolicyEntry',
    'ServiceAuthenticationConfigurationInfo',
    'ServiceCorsConfigurationInfo',
    'ServiceCosmosDbConfigurationInfo',
    'ServiceExportConfigurationInfo',
    'ServicesPatchDescription',
    'ServicesProperties',
    'ServicesResource',
    'ServicesResourceIdentity',
    'SystemData',
    'TrackedResource',
    'OperationPaged',
    'PrivateLinkServicesForEDMUploadDescriptionPaged',
    'PrivateEndpointConnectionPaged',
    'PrivateLinkServicesForM365ComplianceCenterDescriptionPaged',
    'PrivateLinkServicesForM365SecurityCenterDescriptionPaged',
    'PrivateLinkServicesForO365ManagementActivityAPIDescriptionPaged',
    'PrivateLinkServicesForSCCPowershellDescriptionPaged',
    'ProvisioningState',
    'CreatedByType',
    'PrivateEndpointServiceConnectionStatus',
    'PrivateEndpointConnectionProvisioningState',
    'PublicNetworkAccess',
    'Kind',
    'ManagedServiceIdentityType',
    'OperationResultStatus',
]
