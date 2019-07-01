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


class PermissionsOperations(object):
    """PermissionsOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: The API version to use for this operation. Constant value: "2018-01-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-01-01-preview"

        self.config = config

    def list_for_resource_group(
            self, resource_group_name, custom_headers=None, raw=False, **operation_config):
        """Gets all permissions the caller has for a resource group.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Permission
        :rtype:
         ~azure.mgmt.authorization.v2018_01_01_preview.models.PermissionPaged[~azure.mgmt.authorization.v2018_01_01_preview.models.Permission]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_for_resource_group.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
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
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.PermissionPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_for_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/Microsoft.Authorization/permissions'}

    def list_for_resource(
            self, resource_group_name, resource_provider_namespace, parent_resource_path, resource_type, resource_name, custom_headers=None, raw=False, **operation_config):
        """Gets all permissions the caller has for a resource.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param resource_provider_namespace: The namespace of the resource
         provider.
        :type resource_provider_namespace: str
        :param parent_resource_path: The parent resource identity.
        :type parent_resource_path: str
        :param resource_type: The resource type of the resource.
        :type resource_type: str
        :param resource_name: The name of the resource to get the permissions
         for.
        :type resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Permission
        :rtype:
         ~azure.mgmt.authorization.v2018_01_01_preview.models.PermissionPaged[~azure.mgmt.authorization.v2018_01_01_preview.models.Permission]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_for_resource.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'resourceProviderNamespace': self._serialize.url("resource_provider_namespace", resource_provider_namespace, 'str'),
                    'parentResourcePath': self._serialize.url("parent_resource_path", parent_resource_path, 'str', skip_quote=True),
                    'resourceType': self._serialize.url("resource_type", resource_type, 'str', skip_quote=True),
                    'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
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
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.PermissionPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_for_resource.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}/providers/Microsoft.Authorization/permissions'}
