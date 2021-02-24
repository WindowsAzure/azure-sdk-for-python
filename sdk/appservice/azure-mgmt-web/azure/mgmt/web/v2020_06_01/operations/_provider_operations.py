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


class ProviderOperations(object):
    """ProviderOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: API Version. Constant value: "2020-06-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2020-06-01"

        self.config = config

    def get_available_stacks(
            self, os_type_selected=None, custom_headers=None, raw=False, **operation_config):
        """Get available application frameworks and their versions.

        Description for Get available application frameworks and their
        versions.

        :param os_type_selected: Possible values include: 'Windows', 'Linux',
         'WindowsFunctions', 'LinuxFunctions'
        :type os_type_selected: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ApplicationStackResource
        :rtype:
         ~azure.mgmt.web.v2020_06_01.models.ApplicationStackResourcePaged[~azure.mgmt.web.v2020_06_01.models.ApplicationStackResource]
        :raises:
         :class:`DefaultErrorResponseException<azure.mgmt.web.v2020_06_01.models.DefaultErrorResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.get_available_stacks.metadata['url']

                # Construct parameters
                query_parameters = {}
                if os_type_selected is not None:
                    query_parameters['osTypeSelected'] = self._serialize.query("os_type_selected", os_type_selected, 'str')
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
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.DefaultErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.ApplicationStackResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    get_available_stacks.metadata = {'url': '/providers/Microsoft.Web/availableStacks'}

    def list_operations(
            self, custom_headers=None, raw=False, **operation_config):
        """Gets all available operations for the Microsoft.Web resource provider.
        Also exposes resource metric definitions.

        Description for Gets all available operations for the Microsoft.Web
        resource provider. Also exposes resource metric definitions.

        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of CsmOperationDescription
        :rtype:
         ~azure.mgmt.web.v2020_06_01.models.CsmOperationDescriptionPaged[~azure.mgmt.web.v2020_06_01.models.CsmOperationDescription]
        :raises:
         :class:`DefaultErrorResponseException<azure.mgmt.web.v2020_06_01.models.DefaultErrorResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_operations.metadata['url']

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
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.DefaultErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.CsmOperationDescriptionPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_operations.metadata = {'url': '/providers/Microsoft.Web/operations'}

    def get_available_stacks_on_prem(
            self, os_type_selected=None, custom_headers=None, raw=False, **operation_config):
        """Get available application frameworks and their versions.

        Description for Get available application frameworks and their
        versions.

        :param os_type_selected: Possible values include: 'Windows', 'Linux',
         'WindowsFunctions', 'LinuxFunctions'
        :type os_type_selected: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ApplicationStackResource
        :rtype:
         ~azure.mgmt.web.v2020_06_01.models.ApplicationStackResourcePaged[~azure.mgmt.web.v2020_06_01.models.ApplicationStackResource]
        :raises:
         :class:`DefaultErrorResponseException<azure.mgmt.web.v2020_06_01.models.DefaultErrorResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.get_available_stacks_on_prem.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if os_type_selected is not None:
                    query_parameters['osTypeSelected'] = self._serialize.query("os_type_selected", os_type_selected, 'str')
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
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.DefaultErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.ApplicationStackResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    get_available_stacks_on_prem.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Web/availableStacks'}
