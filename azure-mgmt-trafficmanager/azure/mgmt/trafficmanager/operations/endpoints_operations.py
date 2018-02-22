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

import uuid
from msrest.pipeline import ClientRawResponse
from msrestazure.azure_exceptions import CloudError

from .. import models


class EndpointsOperations(object):
    """EndpointsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2017-05-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-05-01"

        self.config = config

    def update(
            self, resource_group_name, profile_name, endpoint_type, endpoint_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Update a Traffic Manager endpoint.

        :param resource_group_name: The name of the resource group containing
         the Traffic Manager endpoint to be updated.
        :type resource_group_name: str
        :param profile_name: The name of the Traffic Manager profile.
        :type profile_name: str
        :param endpoint_type: The type of the Traffic Manager endpoint to be
         updated.
        :type endpoint_type: str
        :param endpoint_name: The name of the Traffic Manager endpoint to be
         updated.
        :type endpoint_name: str
        :param parameters: The Traffic Manager endpoint parameters supplied to
         the Update operation.
        :type parameters: ~azure.mgmt.trafficmanager.models.Endpoint
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Endpoint or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.trafficmanager.models.Endpoint or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'endpointType': self._serialize.url("endpoint_type", endpoint_type, 'str'),
            'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(parameters, 'Endpoint')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Endpoint', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficmanagerprofiles/{profileName}/{endpointType}/{endpointName}'}

    def get(
            self, resource_group_name, profile_name, endpoint_type, endpoint_name, custom_headers=None, raw=False, **operation_config):
        """Gets a Traffic Manager endpoint.

        :param resource_group_name: The name of the resource group containing
         the Traffic Manager endpoint.
        :type resource_group_name: str
        :param profile_name: The name of the Traffic Manager profile.
        :type profile_name: str
        :param endpoint_type: The type of the Traffic Manager endpoint.
        :type endpoint_type: str
        :param endpoint_name: The name of the Traffic Manager endpoint.
        :type endpoint_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Endpoint or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.trafficmanager.models.Endpoint or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'endpointType': self._serialize.url("endpoint_type", endpoint_type, 'str'),
            'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Endpoint', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficmanagerprofiles/{profileName}/{endpointType}/{endpointName}'}

    def create_or_update(
            self, resource_group_name, profile_name, endpoint_type, endpoint_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Create or update a Traffic Manager endpoint.

        :param resource_group_name: The name of the resource group containing
         the Traffic Manager endpoint to be created or updated.
        :type resource_group_name: str
        :param profile_name: The name of the Traffic Manager profile.
        :type profile_name: str
        :param endpoint_type: The type of the Traffic Manager endpoint to be
         created or updated.
        :type endpoint_type: str
        :param endpoint_name: The name of the Traffic Manager endpoint to be
         created or updated.
        :type endpoint_name: str
        :param parameters: The Traffic Manager endpoint parameters supplied to
         the CreateOrUpdate operation.
        :type parameters: ~azure.mgmt.trafficmanager.models.Endpoint
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Endpoint or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.trafficmanager.models.Endpoint or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'endpointType': self._serialize.url("endpoint_type", endpoint_type, 'str'),
            'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(parameters, 'Endpoint')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Endpoint', response)
        if response.status_code == 201:
            deserialized = self._deserialize('Endpoint', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficmanagerprofiles/{profileName}/{endpointType}/{endpointName}'}

    def delete(
            self, resource_group_name, profile_name, endpoint_type, endpoint_name, custom_headers=None, raw=False, **operation_config):
        """Deletes a Traffic Manager endpoint.

        :param resource_group_name: The name of the resource group containing
         the Traffic Manager endpoint to be deleted.
        :type resource_group_name: str
        :param profile_name: The name of the Traffic Manager profile.
        :type profile_name: str
        :param endpoint_type: The type of the Traffic Manager endpoint to be
         deleted.
        :type endpoint_type: str
        :param endpoint_name: The name of the Traffic Manager endpoint to be
         deleted.
        :type endpoint_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: DeleteOperationResult or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.trafficmanager.models.DeleteOperationResult or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'endpointType': self._serialize.url("endpoint_type", endpoint_type, 'str'),
            'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('DeleteOperationResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficmanagerprofiles/{profileName}/{endpointType}/{endpointName}'}
