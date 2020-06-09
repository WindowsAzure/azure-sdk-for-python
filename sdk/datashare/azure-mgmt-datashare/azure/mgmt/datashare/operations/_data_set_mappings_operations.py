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


class DataSetMappingsOperations(object):
    """DataSetMappingsOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: The api version to use. Constant value: "2019-11-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-11-01"

        self.config = config

    def get(
            self, resource_group_name, account_name, share_subscription_name, data_set_mapping_name, custom_headers=None, raw=False, **operation_config):
        """Get DataSetMapping in a shareSubscription.

        Get a DataSetMapping in a shareSubscription.

        :param resource_group_name: The resource group name.
        :type resource_group_name: str
        :param account_name: The name of the share account.
        :type account_name: str
        :param share_subscription_name: The name of the shareSubscription.
        :type share_subscription_name: str
        :param data_set_mapping_name: The name of the dataSetMapping.
        :type data_set_mapping_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: DataSetMapping or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datashare.models.DataSetMapping or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`DataShareErrorException<azure.mgmt.datashare.models.DataShareErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'shareSubscriptionName': self._serialize.url("share_subscription_name", share_subscription_name, 'str'),
            'dataSetMappingName': self._serialize.url("data_set_mapping_name", data_set_mapping_name, 'str')
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
            raise models.DataShareErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('DataSetMapping', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataShare/accounts/{accountName}/shareSubscriptions/{shareSubscriptionName}/dataSetMappings/{dataSetMappingName}'}

    def create(
            self, resource_group_name, account_name, share_subscription_name, data_set_mapping_name, data_set_mapping, custom_headers=None, raw=False, **operation_config):
        """Maps a source data set in the source share to a sink data set in the
        share subscription.
        Enables copying the data set from source to destination.

        Create a DataSetMapping .

        :param resource_group_name: The resource group name.
        :type resource_group_name: str
        :param account_name: The name of the share account.
        :type account_name: str
        :param share_subscription_name: The name of the share subscription
         which will hold the data set sink.
        :type share_subscription_name: str
        :param data_set_mapping_name: The name of the data set mapping to be
         created.
        :type data_set_mapping_name: str
        :param data_set_mapping: Destination data set configuration details.
        :type data_set_mapping: ~azure.mgmt.datashare.models.DataSetMapping
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: DataSetMapping or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datashare.models.DataSetMapping or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`DataShareErrorException<azure.mgmt.datashare.models.DataShareErrorException>`
        """
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'shareSubscriptionName': self._serialize.url("share_subscription_name", share_subscription_name, 'str'),
            'dataSetMappingName': self._serialize.url("data_set_mapping_name", data_set_mapping_name, 'str')
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
        body_content = self._serialize.body(data_set_mapping, 'DataSetMapping')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.DataShareErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('DataSetMapping', response)
        if response.status_code == 201:
            deserialized = self._deserialize('DataSetMapping', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataShare/accounts/{accountName}/shareSubscriptions/{shareSubscriptionName}/dataSetMappings/{dataSetMappingName}'}

    def delete(
            self, resource_group_name, account_name, share_subscription_name, data_set_mapping_name, custom_headers=None, raw=False, **operation_config):
        """Delete DataSetMapping in a shareSubscription.

        Delete a DataSetMapping in a shareSubscription.

        :param resource_group_name: The resource group name.
        :type resource_group_name: str
        :param account_name: The name of the share account.
        :type account_name: str
        :param share_subscription_name: The name of the shareSubscription.
        :type share_subscription_name: str
        :param data_set_mapping_name: The name of the dataSetMapping.
        :type data_set_mapping_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`DataShareErrorException<azure.mgmt.datashare.models.DataShareErrorException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'shareSubscriptionName': self._serialize.url("share_subscription_name", share_subscription_name, 'str'),
            'dataSetMappingName': self._serialize.url("data_set_mapping_name", data_set_mapping_name, 'str')
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
            raise models.DataShareErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataShare/accounts/{accountName}/shareSubscriptions/{shareSubscriptionName}/dataSetMappings/{dataSetMappingName}'}

    def list_by_share_subscription(
            self, resource_group_name, account_name, share_subscription_name, skip_token=None, custom_headers=None, raw=False, **operation_config):
        """List DataSetMappings in a share subscription.

        List DataSetMappings in a share subscription.

        :param resource_group_name: The resource group name.
        :type resource_group_name: str
        :param account_name: The name of the share account.
        :type account_name: str
        :param share_subscription_name: The name of the share subscription.
        :type share_subscription_name: str
        :param skip_token: Continuation token
        :type skip_token: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of DataSetMapping
        :rtype:
         ~azure.mgmt.datashare.models.DataSetMappingPaged[~azure.mgmt.datashare.models.DataSetMapping]
        :raises:
         :class:`DataShareErrorException<azure.mgmt.datashare.models.DataShareErrorException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_share_subscription.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'accountName': self._serialize.url("account_name", account_name, 'str'),
                    'shareSubscriptionName': self._serialize.url("share_subscription_name", share_subscription_name, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if skip_token is not None:
                    query_parameters['$skipToken'] = self._serialize.query("skip_token", skip_token, 'str')

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
                raise models.DataShareErrorException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.DataSetMappingPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_by_share_subscription.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataShare/accounts/{accountName}/shareSubscriptions/{shareSubscriptionName}/dataSetMappings'}
