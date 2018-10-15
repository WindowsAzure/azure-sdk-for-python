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

from .. import models


class BotsOperations(object):
    """BotsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. Current version is 2017-12-01. Constant value: "2018-07-12".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-07-12"

        self.config = config

    def create(
            self, resource_group_name, resource_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Creates a Bot Service. Bot Service is a resource group wide resource
        type.

        :param resource_group_name: The name of the Bot resource group in the
         user subscription.
        :type resource_group_name: str
        :param resource_name: The name of the Bot resource.
        :type resource_name: str
        :param parameters: The parameters to provide for the created bot.
        :type parameters: ~azure.mgmt.botservice.models.Bot
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Bot or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.botservice.models.Bot or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorException<azure.mgmt.botservice.models.ErrorException>`
        """
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
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
        body_content = self._serialize.body(parameters, 'Bot')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Bot', response)
        if response.status_code == 201:
            deserialized = self._deserialize('Bot', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices/{resourceName}'}

    def update(
            self, resource_group_name, resource_name, location=None, tags=None, sku=None, kind=None, etag=None, properties=None, custom_headers=None, raw=False, **operation_config):
        """Updates a Bot Service.

        :param resource_group_name: The name of the Bot resource group in the
         user subscription.
        :type resource_group_name: str
        :param resource_name: The name of the Bot resource.
        :type resource_name: str
        :param location: Specifies the location of the resource.
        :type location: str
        :param tags: Contains resource tags defined as key/value pairs.
        :type tags: dict[str, str]
        :param sku: Gets or sets the SKU of the resource.
        :type sku: ~azure.mgmt.botservice.models.Sku
        :param kind: Required. Gets or sets the Kind of the resource. Possible
         values include: 'sdk', 'designer', 'bot', 'function'
        :type kind: str or ~azure.mgmt.botservice.models.Kind
        :param etag: Entity Tag
        :type etag: str
        :param properties: The set of properties specific to bot resource
        :type properties: ~azure.mgmt.botservice.models.BotProperties
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Bot or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.botservice.models.Bot or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorException<azure.mgmt.botservice.models.ErrorException>`
        """
        parameters = models.Bot(location=location, tags=tags, sku=sku, kind=kind, etag=etag, properties=properties)

        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
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
        body_content = self._serialize.body(parameters, 'Bot')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Bot', response)
        if response.status_code == 201:
            deserialized = self._deserialize('Bot', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices/{resourceName}'}

    def delete(
            self, resource_group_name, resource_name, custom_headers=None, raw=False, **operation_config):
        """Deletes a Bot Service from the resource group. .

        :param resource_group_name: The name of the Bot resource group in the
         user subscription.
        :type resource_group_name: str
        :param resource_name: The name of the Bot resource.
        :type resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorException<azure.mgmt.botservice.models.ErrorException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 204]:
            raise models.ErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices/{resourceName}'}

    def get(
            self, resource_group_name, resource_name, custom_headers=None, raw=False, **operation_config):
        """Returns a BotService specified by the parameters.

        :param resource_group_name: The name of the Bot resource group in the
         user subscription.
        :type resource_group_name: str
        :param resource_name: The name of the Bot resource.
        :type resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Bot or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.botservice.models.Bot or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorException<azure.mgmt.botservice.models.ErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Bot', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices/{resourceName}'}

    def list_by_resource_group(
            self, resource_group_name, custom_headers=None, raw=False, **operation_config):
        """Returns all the resources of a particular type belonging to a resource
        group.

        :param resource_group_name: The name of the Bot resource group in the
         user subscription.
        :type resource_group_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Bot
        :rtype:
         ~azure.mgmt.botservice.models.BotPaged[~azure.mgmt.botservice.models.Bot]
        :raises:
         :class:`ErrorException<azure.mgmt.botservice.models.ErrorException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_resource_group.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=64, min_length=2, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.BotPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.BotPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices'}

    def list(
            self, custom_headers=None, raw=False, **operation_config):
        """Returns all the resources of a particular type belonging to a
        subscription.

        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Bot
        :rtype:
         ~azure.mgmt.botservice.models.BotPaged[~azure.mgmt.botservice.models.Bot]
        :raises:
         :class:`ErrorException<azure.mgmt.botservice.models.ErrorException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.BotPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.BotPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.BotService/botServices'}

    def get_check_name_availability(
            self, name=None, type=None, custom_headers=None, raw=False, **operation_config):
        """Check whether a bot name is available.

        :param name: the name of the bot for which availability needs to be
         checked.
        :type name: str
        :param type: the type of the bot for which availability needs to be
         checked
        :type type: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: CheckNameAvailabilityResponseBody or ClientRawResponse if
         raw=true
        :rtype:
         ~azure.mgmt.botservice.models.CheckNameAvailabilityResponseBody or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorException<azure.mgmt.botservice.models.ErrorException>`
        """
        parameters = models.CheckNameAvailabilityRequestBody(name=name, type=type)

        # Construct URL
        url = self.get_check_name_availability.metadata['url']

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
        body_content = self._serialize.body(parameters, 'CheckNameAvailabilityRequestBody')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('CheckNameAvailabilityResponseBody', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_check_name_availability.metadata = {'url': '/providers/Microsoft.BotService/checkNameAvailability'}
