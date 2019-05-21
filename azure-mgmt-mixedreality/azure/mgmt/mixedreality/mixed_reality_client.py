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
from .operations.operations import Operations
from .operations.spatial_anchors_accounts_operations import SpatialAnchorsAccountsOperations
from . import models


class MixedRealityClientConfiguration(AzureConfiguration):
    """Configuration for MixedRealityClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure subscription ID.
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

        super(MixedRealityClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-mixedreality/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class MixedRealityClient(SDKClient):
    """Mixed Reality Client

    :ivar config: Configuration for client.
    :vartype config: MixedRealityClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.mixedreality.operations.Operations
    :ivar spatial_anchors_accounts: SpatialAnchorsAccounts operations
    :vartype spatial_anchors_accounts: azure.mgmt.mixedreality.operations.SpatialAnchorsAccountsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = MixedRealityClientConfiguration(credentials, subscription_id, base_url)
        super(MixedRealityClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-02-28-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.spatial_anchors_accounts = SpatialAnchorsAccountsOperations(
            self._client, self.config, self._serialize, self._deserialize)

    def check_name_availability_local(
            self, location, name, type, custom_headers=None, raw=False, **operation_config):
        """Check Name Availability for global uniqueness.

        :param location: The location in which uniqueness will be verified.
        :type location: str
        :param name: Resource Name To Verify
        :type name: str
        :param type: Fully qualified resource type which includes provider
         namespace
        :type type: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: CheckNameAvailabilityResponse or ClientRawResponse if
         raw=true
        :rtype: ~azure.mgmt.mixedreality.models.CheckNameAvailabilityResponse
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        check_name_availability = models.CheckNameAvailabilityRequest(name=name, type=type)

        # Construct URL
        url = self.check_name_availability_local.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'location': self._serialize.url("location", location, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
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
        body_content = self._serialize.body(check_name_availability, 'CheckNameAvailabilityRequest')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('CheckNameAvailabilityResponse', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    check_name_availability_local.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.MixedReality/locations/{location}/checkNameAvailability'}
