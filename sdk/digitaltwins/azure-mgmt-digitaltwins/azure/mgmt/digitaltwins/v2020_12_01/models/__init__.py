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
    from ._models_py3 import CheckNameRequest
    from ._models_py3 import CheckNameResult
    from ._models_py3 import ConnectionProperties
    from ._models_py3 import ConnectionPropertiesPrivateEndpoint
    from ._models_py3 import ConnectionPropertiesPrivateLinkServiceConnectionState
    from ._models_py3 import ConnectionState
    from ._models_py3 import DigitalTwinsDescription
    from ._models_py3 import DigitalTwinsEndpointResource
    from ._models_py3 import DigitalTwinsEndpointResourceProperties
    from ._models_py3 import DigitalTwinsIdentity
    from ._models_py3 import DigitalTwinsPatchDescription
    from ._models_py3 import DigitalTwinsPatchProperties
    from ._models_py3 import DigitalTwinsResource
    from ._models_py3 import ErrorDefinition
    from ._models_py3 import ErrorResponse, ErrorResponseException
    from ._models_py3 import EventGrid
    from ._models_py3 import EventHub
    from ._models_py3 import ExternalResource
    from ._models_py3 import GroupIdInformation
    from ._models_py3 import GroupIdInformationProperties
    from ._models_py3 import GroupIdInformationPropertiesModel
    from ._models_py3 import GroupIdInformationResponse
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateEndpointConnection
    from ._models_py3 import PrivateEndpointConnectionProperties
    from ._models_py3 import PrivateEndpointConnectionsResponse
    from ._models_py3 import ServiceBus
except (SyntaxError, ImportError):
    from ._models import CheckNameRequest
    from ._models import CheckNameResult
    from ._models import ConnectionProperties
    from ._models import ConnectionPropertiesPrivateEndpoint
    from ._models import ConnectionPropertiesPrivateLinkServiceConnectionState
    from ._models import ConnectionState
    from ._models import DigitalTwinsDescription
    from ._models import DigitalTwinsEndpointResource
    from ._models import DigitalTwinsEndpointResourceProperties
    from ._models import DigitalTwinsIdentity
    from ._models import DigitalTwinsPatchDescription
    from ._models import DigitalTwinsPatchProperties
    from ._models import DigitalTwinsResource
    from ._models import ErrorDefinition
    from ._models import ErrorResponse, ErrorResponseException
    from ._models import EventGrid
    from ._models import EventHub
    from ._models import ExternalResource
    from ._models import GroupIdInformation
    from ._models import GroupIdInformationProperties
    from ._models import GroupIdInformationPropertiesModel
    from ._models import GroupIdInformationResponse
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import PrivateEndpoint
    from ._models import PrivateEndpointConnection
    from ._models import PrivateEndpointConnectionProperties
    from ._models import PrivateEndpointConnectionsResponse
    from ._models import ServiceBus
from ._paged_models import DigitalTwinsDescriptionPaged
from ._paged_models import DigitalTwinsEndpointResourcePaged
from ._paged_models import OperationPaged
from ._azure_digital_twins_management_client_enums import (
    PublicNetworkAccess,
    ProvisioningState,
    DigitalTwinsIdentityType,
    Reason,
    EndpointProvisioningState,
    AuthenticationType,
    PrivateLinkServiceConnectionStatus,
    ConnectionPropertiesProvisioningState,
)

__all__ = [
    'CheckNameRequest',
    'CheckNameResult',
    'ConnectionProperties',
    'ConnectionPropertiesPrivateEndpoint',
    'ConnectionPropertiesPrivateLinkServiceConnectionState',
    'ConnectionState',
    'DigitalTwinsDescription',
    'DigitalTwinsEndpointResource',
    'DigitalTwinsEndpointResourceProperties',
    'DigitalTwinsIdentity',
    'DigitalTwinsPatchDescription',
    'DigitalTwinsPatchProperties',
    'DigitalTwinsResource',
    'ErrorDefinition',
    'ErrorResponse', 'ErrorResponseException',
    'EventGrid',
    'EventHub',
    'ExternalResource',
    'GroupIdInformation',
    'GroupIdInformationProperties',
    'GroupIdInformationPropertiesModel',
    'GroupIdInformationResponse',
    'Operation',
    'OperationDisplay',
    'PrivateEndpoint',
    'PrivateEndpointConnection',
    'PrivateEndpointConnectionProperties',
    'PrivateEndpointConnectionsResponse',
    'ServiceBus',
    'DigitalTwinsDescriptionPaged',
    'DigitalTwinsEndpointResourcePaged',
    'OperationPaged',
    'PublicNetworkAccess',
    'ProvisioningState',
    'DigitalTwinsIdentityType',
    'Reason',
    'EndpointProvisioningState',
    'AuthenticationType',
    'PrivateLinkServiceConnectionStatus',
    'ConnectionPropertiesProvisioningState',
]
