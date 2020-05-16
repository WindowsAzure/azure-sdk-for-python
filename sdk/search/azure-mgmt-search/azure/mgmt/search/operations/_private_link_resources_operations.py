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


class PrivateLinkResourcesOperations(object):
    """PrivateLinkResourcesOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: The API version to use for each request. The current version is 2019-10-01-Preview. Constant value: "2020-03-13".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2020-03-13"

        self.config = config

    def list_supported(
            self, resource_group_name, search_service_name, search_management_request_options=None, custom_headers=None, raw=False, **operation_config):
        """Gets a list of all supported private link resource types for the given
        service.

        :param resource_group_name: The name of the resource group within the
         current subscription. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param search_service_name: The name of the Azure Cognitive Search
         service associated with the specified resource group.
        :type search_service_name: str
        :param search_management_request_options: Additional parameters for
         the operation
        :type search_management_request_options:
         ~azure.mgmt.search.models.SearchManagementRequestOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PrivateLinkResource
        :rtype:
         ~azure.mgmt.search.models.PrivateLinkResourcePaged[~azure.mgmt.search.models.PrivateLinkResource]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        client_request_id = None
        if search_management_request_options is not None:
            client_request_id = search_management_request_options.client_request_id

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_supported.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'searchServiceName': self._serialize.url("search_service_name", search_service_name, 'str')
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
            if client_request_id is not None:
                header_parameters['x-ms-client-request-id'] = self._serialize.header("client_request_id", client_request_id, 'str')

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
        deserialized = models.PrivateLinkResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_supported.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Search/searchServices/{searchServiceName}/privateLinkResources'}
