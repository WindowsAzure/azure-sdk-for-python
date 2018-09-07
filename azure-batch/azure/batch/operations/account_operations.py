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


class AccountOperations(object):
    """AccountOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client API Version. Constant value: "2018-08-01.7.0".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-08-01.7.0"

        self.config = config

    def list_node_agent_skus(
            self, account_list_node_agent_skus_options=None, custom_headers=None, raw=False, **operation_config):
        """Lists all node agent SKUs supported by the Azure Batch service.

        :param account_list_node_agent_skus_options: Additional parameters for
         the operation
        :type account_list_node_agent_skus_options:
         ~azure.batch.models.AccountListNodeAgentSkusOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of NodeAgentSku
        :rtype:
         ~azure.batch.models.NodeAgentSkuPaged[~azure.batch.models.NodeAgentSku]
        :raises:
         :class:`BatchErrorException<azure.batch.models.BatchErrorException>`
        """
        filter = None
        if account_list_node_agent_skus_options is not None:
            filter = account_list_node_agent_skus_options.filter
        max_results = None
        if account_list_node_agent_skus_options is not None:
            max_results = account_list_node_agent_skus_options.max_results
        timeout = None
        if account_list_node_agent_skus_options is not None:
            timeout = account_list_node_agent_skus_options.timeout
        client_request_id = None
        if account_list_node_agent_skus_options is not None:
            client_request_id = account_list_node_agent_skus_options.client_request_id
        return_client_request_id = None
        if account_list_node_agent_skus_options is not None:
            return_client_request_id = account_list_node_agent_skus_options.return_client_request_id
        ocp_date = None
        if account_list_node_agent_skus_options is not None:
            ocp_date = account_list_node_agent_skus_options.ocp_date

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_node_agent_skus.metadata['url']

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if max_results is not None:
                    query_parameters['maxresults'] = self._serialize.query("max_results", max_results, 'int', maximum=1000, minimum=1)
                if timeout is not None:
                    query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')
            if client_request_id is not None:
                header_parameters['client-request-id'] = self._serialize.header("client_request_id", client_request_id, 'str')
            if return_client_request_id is not None:
                header_parameters['return-client-request-id'] = self._serialize.header("return_client_request_id", return_client_request_id, 'bool')
            if ocp_date is not None:
                header_parameters['ocp-date'] = self._serialize.header("ocp_date", ocp_date, 'rfc-1123')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.BatchErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.NodeAgentSkuPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.NodeAgentSkuPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_node_agent_skus.metadata = {'url': '/nodeagentskus'}

    def list_pool_node_counts(
            self, account_list_pool_node_counts_options=None, custom_headers=None, raw=False, **operation_config):
        """Gets the number of nodes in each state, grouped by pool.

        :param account_list_pool_node_counts_options: Additional parameters
         for the operation
        :type account_list_pool_node_counts_options:
         ~azure.batch.models.AccountListPoolNodeCountsOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PoolNodeCounts
        :rtype:
         ~azure.batch.models.PoolNodeCountsPaged[~azure.batch.models.PoolNodeCounts]
        :raises:
         :class:`BatchErrorException<azure.batch.models.BatchErrorException>`
        """
        filter = None
        if account_list_pool_node_counts_options is not None:
            filter = account_list_pool_node_counts_options.filter
        max_results = None
        if account_list_pool_node_counts_options is not None:
            max_results = account_list_pool_node_counts_options.max_results
        timeout = None
        if account_list_pool_node_counts_options is not None:
            timeout = account_list_pool_node_counts_options.timeout
        client_request_id = None
        if account_list_pool_node_counts_options is not None:
            client_request_id = account_list_pool_node_counts_options.client_request_id
        return_client_request_id = None
        if account_list_pool_node_counts_options is not None:
            return_client_request_id = account_list_pool_node_counts_options.return_client_request_id
        ocp_date = None
        if account_list_pool_node_counts_options is not None:
            ocp_date = account_list_pool_node_counts_options.ocp_date

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_pool_node_counts.metadata['url']

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if max_results is not None:
                    query_parameters['maxresults'] = self._serialize.query("max_results", max_results, 'int', maximum=10, minimum=1)
                if timeout is not None:
                    query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')
            if client_request_id is not None:
                header_parameters['client-request-id'] = self._serialize.header("client_request_id", client_request_id, 'str')
            if return_client_request_id is not None:
                header_parameters['return-client-request-id'] = self._serialize.header("return_client_request_id", return_client_request_id, 'bool')
            if ocp_date is not None:
                header_parameters['ocp-date'] = self._serialize.header("ocp_date", ocp_date, 'rfc-1123')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.BatchErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.PoolNodeCountsPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.PoolNodeCountsPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_pool_node_counts.metadata = {'url': '/nodecounts'}
