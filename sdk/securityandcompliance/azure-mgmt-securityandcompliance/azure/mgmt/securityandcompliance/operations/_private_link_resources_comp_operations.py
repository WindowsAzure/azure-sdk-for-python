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


class PrivateLinkResourcesCompOperations(object):
    """PrivateLinkResourcesCompOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2021-01-11".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2021-01-11"

        self.config = config

    def list_by_service(
            self, resource_group_name, resource_name, custom_headers=None, raw=False, **operation_config):
        """Gets the private link resources that need to be created for a service.

        :param resource_group_name: The name of the resource group that
         contains the service instance.
        :type resource_group_name: str
        :param resource_name: The name of the service instance.
        :type resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PrivateLinkResourceListResult or ClientRawResponse if
         raw=true
        :rtype:
         ~azure.mgmt.securityandcompliance.models.PrivateLinkResourceListResult
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorDetailsException<azure.mgmt.securityandcompliance.models.ErrorDetailsException>`
        """
        # Construct URL
        url = self.list_by_service.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str', max_length=24, min_length=3)
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
            raise models.ErrorDetailsException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('PrivateLinkResourceListResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_by_service.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.SecurityAndCompliance/privateLinkServicesForM365ComplianceCenter/{resourceName}/privateLinkResources'}

    def get(
            self, resource_group_name, resource_name, group_name, custom_headers=None, raw=False, **operation_config):
        """Gets a private link resource that need to be created for a service.

        :param resource_group_name: The name of the resource group that
         contains the service instance.
        :type resource_group_name: str
        :param resource_name: The name of the service instance.
        :type resource_name: str
        :param group_name: The name of the private link resource group.
        :type group_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PrivateLinkResource or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.securityandcompliance.models.PrivateLinkResource
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorDetailsException<azure.mgmt.securityandcompliance.models.ErrorDetailsException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str', max_length=24, min_length=3),
            'groupName': self._serialize.url("group_name", group_name, 'str')
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
            raise models.ErrorDetailsException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('PrivateLinkResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.SecurityAndCompliance/privateLinkServicesForM365ComplianceCenter/{resourceName}/privateLinkResources/{groupName}'}
