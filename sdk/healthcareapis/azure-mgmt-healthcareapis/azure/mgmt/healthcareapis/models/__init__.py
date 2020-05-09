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
    from ._models_py3 import CheckNameAvailabilityParameters
    from ._models_py3 import ErrorDetails, ErrorDetailsException
    from ._models_py3 import ErrorDetailsInternal
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationResultsDescription
    from ._models_py3 import Resource
    from ._models_py3 import ResourceIdentity
    from ._models_py3 import ServiceAccessPolicyEntry
    from ._models_py3 import ServiceAuthenticationConfigurationInfo
    from ._models_py3 import ServiceCorsConfigurationInfo
    from ._models_py3 import ServiceCosmosDbConfigurationInfo
    from ._models_py3 import ServiceExportConfigurationInfo
    from ._models_py3 import ServicesDescription
    from ._models_py3 import ServicesNameAvailabilityInfo
    from ._models_py3 import ServicesPatchDescription
    from ._models_py3 import ServicesProperties
except (SyntaxError, ImportError):
    from ._models import CheckNameAvailabilityParameters
    from ._models import ErrorDetails, ErrorDetailsException
    from ._models import ErrorDetailsInternal
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import OperationResultsDescription
    from ._models import Resource
    from ._models import ResourceIdentity
    from ._models import ServiceAccessPolicyEntry
    from ._models import ServiceAuthenticationConfigurationInfo
    from ._models import ServiceCorsConfigurationInfo
    from ._models import ServiceCosmosDbConfigurationInfo
    from ._models import ServiceExportConfigurationInfo
    from ._models import ServicesDescription
    from ._models import ServicesNameAvailabilityInfo
    from ._models import ServicesPatchDescription
    from ._models import ServicesProperties
from ._paged_models import OperationPaged
from ._paged_models import ServicesDescriptionPaged
from ._healthcare_apis_management_client_enums import (
    ProvisioningState,
    Kind,
    ManagedServiceIdentityType,
    ServiceNameUnavailabilityReason,
    OperationResultStatus,
)

__all__ = [
    'CheckNameAvailabilityParameters',
    'ErrorDetails', 'ErrorDetailsException',
    'ErrorDetailsInternal',
    'Operation',
    'OperationDisplay',
    'OperationResultsDescription',
    'Resource',
    'ResourceIdentity',
    'ServiceAccessPolicyEntry',
    'ServiceAuthenticationConfigurationInfo',
    'ServiceCorsConfigurationInfo',
    'ServiceCosmosDbConfigurationInfo',
    'ServiceExportConfigurationInfo',
    'ServicesDescription',
    'ServicesNameAvailabilityInfo',
    'ServicesPatchDescription',
    'ServicesProperties',
    'ServicesDescriptionPaged',
    'OperationPaged',
    'ProvisioningState',
    'Kind',
    'ManagedServiceIdentityType',
    'ServiceNameUnavailabilityReason',
    'OperationResultStatus',
]
