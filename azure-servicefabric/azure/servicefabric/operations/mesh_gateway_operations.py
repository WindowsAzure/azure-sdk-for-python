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

from msrest.pipeline import ClientRawResponse

from .. import models


class MeshGatewayOperations(object):
    """MeshGatewayOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: The version of the API. This parameter is required and its value must be '6.4-preview'. Constant value: "6.4-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config
        self.api_version = "6.4-preview"

    def create_or_update(
            self, gateway_resource_name, gateway_resource_description, custom_headers=None, raw=False, **operation_config):
        """Creates or updates a Gateway resource.

        Creates a Gateway resource with the specified name, description and
        properties. If Gateway resource with the same name exists, then it is
        updated with the specified description and properties. Use Gateway
        resource to provide public connectivity to application services.

        :param gateway_resource_name: The identity of the gateway.
        :type gateway_resource_name: str
        :param gateway_resource_description: Description for creating a
         Gateway resource.
        :type gateway_resource_description:
         ~azure.servicefabric.models.GatewayResourceDescription
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: GatewayResourceDescription or ClientRawResponse if raw=true
        :rtype: ~azure.servicefabric.models.GatewayResourceDescription or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`FabricErrorException<azure.servicefabric.models.FabricErrorException>`
        """
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'gatewayResourceName': self._serialize.url("gateway_resource_name", gateway_resource_name, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(gateway_resource_description, 'GatewayResourceDescription')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201, 202]:
            raise models.FabricErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('GatewayResourceDescription', response)
        if response.status_code == 201:
            deserialized = self._deserialize('GatewayResourceDescription', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/Resources/Gateways/{gatewayResourceName}'}

    def get(
            self, gateway_resource_name, custom_headers=None, raw=False, **operation_config):
        """Gets the Gateway resource with the given name.

        Gets the information about the Gateway resource with the given name.
        The information include the description and other properties of the
        Gateway.

        :param gateway_resource_name: The identity of the gateway.
        :type gateway_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: GatewayResourceDescription or ClientRawResponse if raw=true
        :rtype: ~azure.servicefabric.models.GatewayResourceDescription or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`FabricErrorException<azure.servicefabric.models.FabricErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'gatewayResourceName': self._serialize.url("gateway_resource_name", gateway_resource_name, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.FabricErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('GatewayResourceDescription', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/Resources/Gateways/{gatewayResourceName}'}

    def delete(
            self, gateway_resource_name, custom_headers=None, raw=False, **operation_config):
        """Deletes the Gateway resource.

        Deletes the Gateway resource identified by the name.

        :param gateway_resource_name: The identity of the gateway.
        :type gateway_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`FabricErrorException<azure.servicefabric.models.FabricErrorException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'gatewayResourceName': self._serialize.url("gateway_resource_name", gateway_resource_name, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202, 204]:
            raise models.FabricErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/Resources/Gateways/{gatewayResourceName}'}

    def list(
            self, custom_headers=None, raw=False, **operation_config):
        """Lists all the gateway resources.

        Gets the information about all gateway resources in a given resource
        group. The information include the description and other properties of
        the Gateway.

        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PagedGatewayResourceDescriptionList or ClientRawResponse if
         raw=true
        :rtype:
         ~azure.servicefabric.models.PagedGatewayResourceDescriptionList or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`FabricErrorException<azure.servicefabric.models.FabricErrorException>`
        """
        # Construct URL
        url = self.list.metadata['url']

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.FabricErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PagedGatewayResourceDescriptionList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/Resources/Gateways'}
