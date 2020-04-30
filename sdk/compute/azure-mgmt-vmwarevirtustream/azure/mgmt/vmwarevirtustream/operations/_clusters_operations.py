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
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling

from .. import models


class ClustersOperations(object):
    """ClustersOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of Azure VMware Solution by Virtustream API to be used with the client request. Constant value: "2019-08-09-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-08-09-preview"

        self.config = config

    def list(
            self, resource_group_name, private_cloud_name, custom_headers=None, raw=False, **operation_config):
        """List clusters in a private cloud.

        :param resource_group_name: Name of the resource group within the
         Azure subscription
        :type resource_group_name: str
        :param private_cloud_name: Name of the private cloud
        :type private_cloud_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Cluster
        :rtype:
         ~azure.mgmt.vmwarevirtustream.models.ClusterPaged[~azure.mgmt.vmwarevirtustream.models.Cluster]
        :raises:
         :class:`ApiErrorException<azure.mgmt.vmwarevirtustream.models.ApiErrorException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'privateCloudName': self._serialize.url("private_cloud_name", private_cloud_name, 'str')
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
                raise models.ApiErrorException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.ClusterPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareVirtustream/privateClouds/{privateCloudName}/clusters'}

    def get(
            self, resource_group_name, private_cloud_name, cluster_name, custom_headers=None, raw=False, **operation_config):
        """Get a cluster by name in a private cloud.

        :param resource_group_name: Name of the resource group within the
         Azure subscription
        :type resource_group_name: str
        :param private_cloud_name: Name of the private cloud
        :type private_cloud_name: str
        :param cluster_name: Name of the cluster in the private cloud
        :type cluster_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Cluster or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.vmwarevirtustream.models.Cluster or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ApiErrorException<azure.mgmt.vmwarevirtustream.models.ApiErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'privateCloudName': self._serialize.url("private_cloud_name", private_cloud_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str')
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
            raise models.ApiErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('Cluster', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareVirtustream/privateClouds/{privateCloudName}/clusters/{clusterName}'}


    def _create_or_update_initial(
            self, resource_group_name, private_cloud_name, cluster_name, properties=None, custom_headers=None, raw=False, **operation_config):
        cluster = models.Cluster(properties=properties)

        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'privateCloudName': self._serialize.url("private_cloud_name", private_cloud_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str')
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
        body_content = self._serialize.body(cluster, 'Cluster')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ApiErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Cluster', response)
        if response.status_code == 201:
            deserialized = self._deserialize('Cluster', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create_or_update(
            self, resource_group_name, private_cloud_name, cluster_name, properties=None, custom_headers=None, raw=False, polling=True, **operation_config):
        """Create or update a cluster in a private cloud.

        :param resource_group_name: Name of the resource group within the
         Azure subscription
        :type resource_group_name: str
        :param private_cloud_name: The name of the private cloud.
        :type private_cloud_name: str
        :param cluster_name: Name of the cluster in the private cloud
        :type cluster_name: str
        :param properties: The properties of a cluster resource
        :type properties:
         ~azure.mgmt.vmwarevirtustream.models.ClusterProperties
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns Cluster or
         ClientRawResponse<Cluster> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.vmwarevirtustream.models.Cluster]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.vmwarevirtustream.models.Cluster]]
        :raises:
         :class:`ApiErrorException<azure.mgmt.vmwarevirtustream.models.ApiErrorException>`
        """
        raw_result = self._create_or_update_initial(
            resource_group_name=resource_group_name,
            private_cloud_name=private_cloud_name,
            cluster_name=cluster_name,
            properties=properties,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('Cluster', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareVirtustream/privateClouds/{privateCloudName}/clusters/{clusterName}'}


    def _update_initial(
            self, resource_group_name, private_cloud_name, cluster_name, properties=None, custom_headers=None, raw=False, **operation_config):
        cluster = models.Cluster(properties=properties)

        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'privateCloudName': self._serialize.url("private_cloud_name", private_cloud_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str')
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
        body_content = self._serialize.body(cluster, 'Cluster')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ApiErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Cluster', response)
        if response.status_code == 201:
            deserialized = self._deserialize('Cluster', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def update(
            self, resource_group_name, private_cloud_name, cluster_name, properties=None, custom_headers=None, raw=False, polling=True, **operation_config):
        """Update a cluster in a private cloud.

        :param resource_group_name: Name of the resource group within the
         Azure subscription
        :type resource_group_name: str
        :param private_cloud_name: Name of the private cloud
        :type private_cloud_name: str
        :param cluster_name: Name of the cluster in the private cloud
        :type cluster_name: str
        :param properties: The properties of a cluster resource
        :type properties:
         ~azure.mgmt.vmwarevirtustream.models.ClusterProperties
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns Cluster or
         ClientRawResponse<Cluster> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.vmwarevirtustream.models.Cluster]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.vmwarevirtustream.models.Cluster]]
        :raises:
         :class:`ApiErrorException<azure.mgmt.vmwarevirtustream.models.ApiErrorException>`
        """
        raw_result = self._update_initial(
            resource_group_name=resource_group_name,
            private_cloud_name=private_cloud_name,
            cluster_name=cluster_name,
            properties=properties,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('Cluster', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareVirtustream/privateClouds/{privateCloudName}/clusters/{clusterName}'}


    def _delete_initial(
            self, resource_group_name, private_cloud_name, cluster_name, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'privateCloudName': self._serialize.url("private_cloud_name", private_cloud_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str')
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

        if response.status_code not in [200, 202, 204]:
            raise models.ApiErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def delete(
            self, resource_group_name, private_cloud_name, cluster_name, custom_headers=None, raw=False, polling=True, **operation_config):
        """Delete a cluster in a private cloud.

        :param resource_group_name: Name of the resource group within the
         Azure subscription
        :type resource_group_name: str
        :param private_cloud_name: Name of the private cloud
        :type private_cloud_name: str
        :param cluster_name: Name of the cluster in the private cloud
        :type cluster_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns None or
         ClientRawResponse<None> if raw==True
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[None]]
        :raises:
         :class:`ApiErrorException<azure.mgmt.vmwarevirtustream.models.ApiErrorException>`
        """
        raw_result = self._delete_initial(
            resource_group_name=resource_group_name,
            private_cloud_name=private_cloud_name,
            cluster_name=cluster_name,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            if raw:
                client_raw_response = ClientRawResponse(None, response)
                return client_raw_response

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareVirtustream/privateClouds/{privateCloudName}/clusters/{clusterName}'}
