# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.pipeline import ClientRawResponse
from msrestazure.azure_operation import AzureOperationPoller
import uuid

from .. import models


class CustomDomainsOperations(object):
    """CustomDomainsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    """

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config

    def list_by_endpoint(
            self, endpoint_name, profile_name, resource_group_name, custom_headers={}, raw=False, **operation_config):
        """
        Lists the existing CDN custom domains within an endpoint.

        :param endpoint_name: Name of the endpoint within the CDN profile.
        :type endpoint_name: str
        :param profile_name: Name of the CDN profile within the resource
         group.
        :type profile_name: str
        :param resource_group_name: Name of the resource group within the
         Azure subscription.
        :type resource_group_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`CustomDomainPaged
         <cdnmanagementclient.models.CustomDomainPaged>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/endpoints/{endpointName}/customDomains'
                path_format_arguments = {
                    'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
                    'profileName': self._serialize.url("profile_name", profile_name, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

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
            response = self._client.send(
                request, header_parameters, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.CustomDomainPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.CustomDomainPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized

    def get(
            self, custom_domain_name, endpoint_name, profile_name, resource_group_name, custom_headers={}, raw=False, **operation_config):
        """
        Gets an existing CDN custom domain within an endpoint.

        :param custom_domain_name: Name of the custom domain within an
         endpoint.
        :type custom_domain_name: str
        :param endpoint_name: Name of the endpoint within the CDN profile.
        :type endpoint_name: str
        :param profile_name: Name of the CDN profile within the resource
         group.
        :type profile_name: str
        :param resource_group_name: Name of the resource group within the
         Azure subscription.
        :type resource_group_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`CustomDomain
         <cdnmanagementclient.models.CustomDomain>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/endpoints/{endpointName}/customDomains/{customDomainName}'
        path_format_arguments = {
            'customDomainName': self._serialize.url("custom_domain_name", custom_domain_name, 'str'),
            'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

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
        response = self._client.send(request, header_parameters, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('CustomDomain', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create(
            self, custom_domain_name, endpoint_name, profile_name, resource_group_name, host_name, custom_headers={}, raw=False, **operation_config):
        """
        Creates a new CDN custom domain within an endpoint.

        :param custom_domain_name: Name of the custom domain within an
         endpoint.
        :type custom_domain_name: str
        :param endpoint_name: Name of the endpoint within the CDN profile.
        :type endpoint_name: str
        :param profile_name: Name of the CDN profile within the resource
         group.
        :type profile_name: str
        :param resource_group_name: Name of the resource group within the
         Azure subscription.
        :type resource_group_name: str
        :param host_name: The host name of the custom domain. Must be a
         domain name.
        :type host_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :rtype:
         :class:`AzureOperationPoller<msrestazure.azure_operation.AzureOperationPoller>`
         instance that returns :class:`CustomDomain
         <cdnmanagementclient.models.CustomDomain>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        """
        custom_domain_properties = models.CustomDomainParameters(host_name=host_name)

        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/endpoints/{endpointName}/customDomains/{customDomainName}'
        path_format_arguments = {
            'customDomainName': self._serialize.url("custom_domain_name", custom_domain_name, 'str'),
            'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

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
        body_content = self._serialize.body(custom_domain_properties, 'CustomDomainParameters')

        # Construct and send request
        def long_running_send():

            request = self._client.put(url, query_parameters)
            return self._client.send(
                request, header_parameters, body_content, **operation_config)

        def get_long_running_status(status_link, headers={}):

            request = self._client.get(status_link)
            request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [201, 202]:
                raise models.ErrorResponseException(self._deserialize, response)

            deserialized = None

            if response.status_code == 201:
                deserialized = self._deserialize('CustomDomain', response)
            if response.status_code == 202:
                deserialized = self._deserialize('CustomDomain', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        if raw:
            response = long_running_send()
            return get_long_running_output(response)

        long_running_operation_timeout = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        return AzureOperationPoller(
            long_running_send, get_long_running_output,
            get_long_running_status, long_running_operation_timeout)

    def update(
            self, custom_domain_name, endpoint_name, profile_name, resource_group_name, host_name, custom_headers={}, raw=False, **operation_config):
        """
        Updates an existing CDN custom domain within an endpoint.

        :param custom_domain_name: Name of the custom domain within an
         endpoint.
        :type custom_domain_name: str
        :param endpoint_name: Name of the endpoint within the CDN profile.
        :type endpoint_name: str
        :param profile_name: Name of the CDN profile within the resource
         group.
        :type profile_name: str
        :param resource_group_name: Name of the resource group within the
         Azure subscription.
        :type resource_group_name: str
        :param host_name: The host name of the custom domain. Must be a
         domain name.
        :type host_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`ErrorResponse
         <cdnmanagementclient.models.ErrorResponse>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        """
        custom_domain_properties = models.CustomDomainParameters(host_name=host_name)

        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/endpoints/{endpointName}/customDomains/{customDomainName}'
        path_format_arguments = {
            'customDomainName': self._serialize.url("custom_domain_name", custom_domain_name, 'str'),
            'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

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
        body_content = self._serialize.body(custom_domain_properties, 'CustomDomainParameters')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, **operation_config)

        if response.status_code < 200 or response.status_code >= 300:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def delete_if_exists(
            self, custom_domain_name, endpoint_name, profile_name, resource_group_name, custom_headers={}, raw=False, **operation_config):
        """
        Deletes an existing CDN custom domain within an endpoint.

        :param custom_domain_name: Name of the custom domain within an
         endpoint.
        :type custom_domain_name: str
        :param endpoint_name: Name of the endpoint within the CDN profile.
        :type endpoint_name: str
        :param profile_name: Name of the CDN profile within the resource
         group.
        :type profile_name: str
        :param resource_group_name: Name of the resource group within the
         Azure subscription.
        :type resource_group_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :rtype:
         :class:`AzureOperationPoller<msrestazure.azure_operation.AzureOperationPoller>`
         instance that returns :class:`CustomDomain
         <cdnmanagementclient.models.CustomDomain>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/endpoints/{endpointName}/customDomains/{customDomainName}'
        path_format_arguments = {
            'customDomainName': self._serialize.url("custom_domain_name", custom_domain_name, 'str'),
            'endpointName': self._serialize.url("endpoint_name", endpoint_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

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
        def long_running_send():

            request = self._client.delete(url, query_parameters)
            return self._client.send(request, header_parameters, **operation_config)

        def get_long_running_status(status_link, headers={}):

            request = self._client.get(status_link)
            request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 202, 204]:
                raise models.ErrorResponseException(self._deserialize, response)

            deserialized = None

            if response.status_code == 202:
                deserialized = self._deserialize('CustomDomain', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        if raw:
            response = long_running_send()
            return get_long_running_output(response)

        long_running_operation_timeout = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        return AzureOperationPoller(
            long_running_send, get_long_running_output,
            get_long_running_status, long_running_operation_timeout)
