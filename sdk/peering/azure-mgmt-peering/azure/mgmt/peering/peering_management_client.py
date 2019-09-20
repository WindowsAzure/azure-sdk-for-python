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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from msrest.pipeline import ClientRawResponse
import uuid
from .operations.legacy_peerings_operations import LegacyPeeringsOperations
from .operations.operations import Operations
from .operations.peer_asns_operations import PeerAsnsOperations
from .operations.peering_locations_operations import PeeringLocationsOperations
from .operations.peerings_operations import PeeringsOperations
from .operations.peering_service_locations_operations import PeeringServiceLocationsOperations
from .operations.peering_service_prefixes_operations import PeeringServicePrefixesOperations
from .operations.prefixes_operations import PrefixesOperations
from .operations.peering_service_providers_operations import PeeringServiceProvidersOperations
from .operations.peering_services_operations import PeeringServicesOperations
from . import models


class PeeringManagementClientConfiguration(AzureConfiguration):
    """Configuration for PeeringManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The Azure subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(PeeringManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-peering/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class PeeringManagementClient(SDKClient):
    """APIs to manage Peering resources through the Azure Resource Manager.

    :ivar config: Configuration for client.
    :vartype config: PeeringManagementClientConfiguration

    :ivar legacy_peerings: LegacyPeerings operations
    :vartype legacy_peerings: azure.mgmt.peering.operations.LegacyPeeringsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.peering.operations.Operations
    :ivar peer_asns: PeerAsns operations
    :vartype peer_asns: azure.mgmt.peering.operations.PeerAsnsOperations
    :ivar peering_locations: PeeringLocations operations
    :vartype peering_locations: azure.mgmt.peering.operations.PeeringLocationsOperations
    :ivar peerings: Peerings operations
    :vartype peerings: azure.mgmt.peering.operations.PeeringsOperations
    :ivar peering_service_locations: PeeringServiceLocations operations
    :vartype peering_service_locations: azure.mgmt.peering.operations.PeeringServiceLocationsOperations
    :ivar peering_service_prefixes: PeeringServicePrefixes operations
    :vartype peering_service_prefixes: azure.mgmt.peering.operations.PeeringServicePrefixesOperations
    :ivar prefixes: Prefixes operations
    :vartype prefixes: azure.mgmt.peering.operations.PrefixesOperations
    :ivar peering_service_providers: PeeringServiceProviders operations
    :vartype peering_service_providers: azure.mgmt.peering.operations.PeeringServiceProvidersOperations
    :ivar peering_services: PeeringServices operations
    :vartype peering_services: azure.mgmt.peering.operations.PeeringServicesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The Azure subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = PeeringManagementClientConfiguration(credentials, subscription_id, base_url)
        super(PeeringManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-08-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.legacy_peerings = LegacyPeeringsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peer_asns = PeerAsnsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_locations = PeeringLocationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peerings = PeeringsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_service_locations = PeeringServiceLocationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_service_prefixes = PeeringServicePrefixesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.prefixes = PrefixesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_service_providers = PeeringServiceProvidersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_services = PeeringServicesOperations(
            self._client, self.config, self._serialize, self._deserialize)

    def check_service_provider_availability(
            self, peering_service_location=None, peering_service_provider=None, custom_headers=None, raw=False, **operation_config):
        """Checks if the peering service provider is present within 1000 miles of
        customer's location.

        :param peering_service_location: Gets or sets the
         PeeringServiceLocation
        :type peering_service_location: str
        :param peering_service_provider: Gets or sets the
         PeeringServiceProvider
        :type peering_service_provider: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: enum or ClientRawResponse if raw=true
        :rtype: str or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.peering.models.ErrorResponseException>`
        """
        check_service_provider_availability_input = models.CheckServiceProviderAvailabilityInput(peering_service_location=peering_service_location, peering_service_provider=peering_service_provider)

        # Construct URL
        url = self.check_service_provider_availability.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(check_service_provider_availability_input, 'CheckServiceProviderAvailabilityInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('str', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    check_service_provider_availability.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Peering/CheckServiceProviderAvailability'}
