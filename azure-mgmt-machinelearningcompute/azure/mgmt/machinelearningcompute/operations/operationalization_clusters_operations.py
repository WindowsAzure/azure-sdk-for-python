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
from msrestazure.azure_operation import AzureOperationPoller

from .. import models


class OperationalizationClustersOperations(object):
    """OperationalizationClustersOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    :ivar api_version: The version of the Microsoft.MachineLearningCompute resource provider API to use. Constant value: "2017-08-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-08-01-preview"

        self.config = config

    def create_or_update(
            self, resource_group_name, cluster_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Create or update an operationalization cluster.

        :param resource_group_name: Name of the resource group in which the
         cluster is located.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster.
        :type cluster_name: str
        :param parameters: Parameters supplied to create or update an
         Operationalization cluster.
        :type parameters:
         ~azure.mgmt.machinelearningcompute.models.OperationalizationCluster
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns
         OperationalizationCluster or ClientRawResponse if raw=true
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.machinelearningcompute.models.OperationalizationCluster]
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseWrapperException<azure.mgmt.machinelearningcompute.models.ErrorResponseWrapperException>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningCompute/operationalizationClusters/{clusterName}'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str', max_length=90, min_length=1, pattern=r'^[a-zA-Z][-\w\._\(\)]+[a-zA-Z0-9]$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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
        body_content = self._serialize.body(parameters, 'OperationalizationCluster')

        # Construct and send request
        def long_running_send():

            request = self._client.put(url, query_parameters)
            return self._client.send(
                request, header_parameters, body_content, **operation_config)

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 201]:
                raise models.ErrorResponseWrapperException(self._deserialize, response)

            deserialized = None

            if response.status_code == 200:
                deserialized = self._deserialize('OperationalizationCluster', response)
            if response.status_code == 201:
                deserialized = self._deserialize('OperationalizationCluster', response)

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

    def get(
            self, resource_group_name, cluster_name, custom_headers=None, raw=False, **operation_config):
        """Gets the operationalization cluster resource view. Note that the
        credentials are not returned by this call. Call ListKeys to get them.

        :param resource_group_name: Name of the resource group in which the
         cluster is located.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster.
        :type cluster_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: OperationalizationCluster or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.machinelearningcompute.models.OperationalizationCluster or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseWrapperException<azure.mgmt.machinelearningcompute.models.ErrorResponseWrapperException>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningCompute/operationalizationClusters/{clusterName}'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str', max_length=90, min_length=1, pattern=r'^[a-zA-Z][-\w\._\(\)]+[a-zA-Z0-9]$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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
            raise models.ErrorResponseWrapperException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('OperationalizationCluster', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def update(
            self, resource_group_name, cluster_name, tags=None, custom_headers=None, raw=False, **operation_config):
        """The PATCH operation can be used to update only the tags for a cluster.
        Use PUT operation to update other properties.

        :param resource_group_name: Name of the resource group in which the
         cluster is located.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster.
        :type cluster_name: str
        :param tags: Gets or sets a list of key value pairs that describe the
         resource. These tags can be used in viewing and grouping this resource
         (across resource groups). A maximum of 15 tags can be provided for a
         resource. Each tag must have a key no greater in length than 128
         characters and a value no greater in length than 256 characters.
        :type tags: dict[str, str]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: OperationalizationCluster or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.machinelearningcompute.models.OperationalizationCluster or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseWrapperException<azure.mgmt.machinelearningcompute.models.ErrorResponseWrapperException>`
        """
        parameters = models.OperationalizationClusterUpdateParameters(tags=tags)

        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningCompute/operationalizationClusters/{clusterName}'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str', max_length=90, min_length=1, pattern=r'^[a-zA-Z][-\w\._\(\)]+[a-zA-Z0-9]$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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
        body_content = self._serialize.body(parameters, 'OperationalizationClusterUpdateParameters')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseWrapperException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('OperationalizationCluster', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def delete(
            self, resource_group_name, cluster_name, delete_all=None, custom_headers=None, raw=False, **operation_config):
        """Deletes the specified cluster.

        :param resource_group_name: Name of the resource group in which the
         cluster is located.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster.
        :type cluster_name: str
        :param delete_all: If true, deletes all resources associated with this
         cluster.
        :type delete_all: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns None or
         ClientRawResponse if raw=true
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseWrapperException<azure.mgmt.machinelearningcompute.models.ErrorResponseWrapperException>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningCompute/operationalizationClusters/{clusterName}'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str', max_length=90, min_length=1, pattern=r'^[a-zA-Z][-\w\._\(\)]+[a-zA-Z0-9]$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
        if delete_all is not None:
            query_parameters['deleteAll'] = self._serialize.query("delete_all", delete_all, 'bool')

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

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [202, 204]:
                raise models.ErrorResponseWrapperException(self._deserialize, response)

            if raw:
                client_raw_response = ClientRawResponse(None, response)
                client_raw_response.add_headers({
                    'Location': 'str',
                })
                return client_raw_response

        if raw:
            response = long_running_send()
            return get_long_running_output(response)

        long_running_operation_timeout = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        return AzureOperationPoller(
            long_running_send, get_long_running_output,
            get_long_running_status, long_running_operation_timeout)

    def list_keys(
            self, resource_group_name, cluster_name, custom_headers=None, raw=False, **operation_config):
        """Gets the credentials for the specified cluster such as Storage, ACR and
        ACS credentials. This is a long running operation because it fetches
        keys from dependencies.

        :param resource_group_name: Name of the resource group in which the
         cluster is located.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster.
        :type cluster_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: OperationalizationClusterCredentials or ClientRawResponse if
         raw=true
        :rtype:
         ~azure.mgmt.machinelearningcompute.models.OperationalizationClusterCredentials
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningCompute/operationalizationClusters/{clusterName}/listKeys'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str', max_length=90, min_length=1, pattern=r'^[a-zA-Z][-\w\._\(\)]+[a-zA-Z0-9]$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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
        request = self._client.post(url, query_parameters)
        response = self._client.send(request, header_parameters, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('OperationalizationClusterCredentials', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def check_system_services_updates_available(
            self, resource_group_name, cluster_name, custom_headers=None, raw=False, **operation_config):
        """Checks if updates are available for system services in the cluster.

        :param resource_group_name: Name of the resource group in which the
         cluster is located.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster.
        :type cluster_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: CheckSystemServicesUpdatesAvailableResponse or
         ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.machinelearningcompute.models.CheckSystemServicesUpdatesAvailableResponse
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningCompute/operationalizationClusters/{clusterName}/checkSystemServicesUpdatesAvailable'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str', max_length=90, min_length=1, pattern=r'^[a-zA-Z][-\w\._\(\)]+[a-zA-Z0-9]$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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
        request = self._client.post(url, query_parameters)
        response = self._client.send(request, header_parameters, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('CheckSystemServicesUpdatesAvailableResponse', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def update_system_services(
            self, resource_group_name, cluster_name, custom_headers=None, raw=False, **operation_config):
        """Updates system services in a cluster.

        :param resource_group_name: Name of the resource group in which the
         cluster is located.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster.
        :type cluster_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns
         UpdateSystemServicesResponse or ClientRawResponse if raw=true
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.machinelearningcompute.models.UpdateSystemServicesResponse]
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningCompute/operationalizationClusters/{clusterName}/updateSystemServices'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str', max_length=90, min_length=1, pattern=r'^[a-zA-Z][-\w\._\(\)]+[a-zA-Z0-9]$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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

            request = self._client.post(url, query_parameters)
            return self._client.send(request, header_parameters, **operation_config)

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 202]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            deserialized = None
            header_dict = {}

            if response.status_code == 200:
                deserialized = self._deserialize('UpdateSystemServicesResponse', response)
                header_dict = {
                    'Location': 'str',
                }

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                client_raw_response.add_headers(header_dict)
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

    def list_by_resource_group(
            self, resource_group_name, skiptoken=None, custom_headers=None, raw=False, **operation_config):
        """Gets the clusters in the specified resource group.

        :param resource_group_name: Name of the resource group in which the
         cluster is located.
        :type resource_group_name: str
        :param skiptoken: Continuation token for pagination.
        :type skiptoken: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of OperationalizationCluster
        :rtype:
         ~azure.mgmt.machinelearningcompute.models.OperationalizationClusterPaged[~azure.mgmt.machinelearningcompute.models.OperationalizationCluster]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningCompute/operationalizationClusters'
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')

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
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.OperationalizationClusterPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.OperationalizationClusterPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized

    def list_by_subscription_id(
            self, skiptoken=None, custom_headers=None, raw=False, **operation_config):
        """Gets the operationalization clusters in the specified subscription.

        :param skiptoken: Continuation token for pagination.
        :type skiptoken: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of OperationalizationCluster
        :rtype:
         ~azure.mgmt.machinelearningcompute.models.OperationalizationClusterPaged[~azure.mgmt.machinelearningcompute.models.OperationalizationCluster]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningCompute/operationalizationClusters'
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')

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
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.OperationalizationClusterPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.OperationalizationClusterPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
