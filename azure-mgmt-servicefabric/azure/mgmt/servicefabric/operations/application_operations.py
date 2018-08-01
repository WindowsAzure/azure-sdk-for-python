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


class ApplicationOperations(object):
    """ApplicationOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config

    def get(
            self, resource_group_name, cluster_name, application_name, api_version, custom_headers=None, raw=False, **operation_config):
        """Returns an application resource with the specified name.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster resource
        :type cluster_name: str
        :param application_name: The name of the application resource.
        :type application_name: str
        :param api_version: The version of the API.
        :type api_version: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ApplicationResource or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.servicefabric.models.ApplicationResource or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabric.models.ErrorModelException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str'),
            'applicationName': self._serialize.url("application_name", application_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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
            raise models.ErrorModelException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ApplicationResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabric/clusters/{clusterName}/applications/{applicationName}'}


    def _put_initial(
            self, resource_group_name, cluster_name, application_name, api_version, parameters, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.put.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str'),
            'applicationName': self._serialize.url("application_name", application_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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
        body_content = self._serialize.body(parameters, 'ApplicationResource')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [202]:
            raise models.ErrorModelException(self._deserialize, response)

        deserialized = None

        if response.status_code == 202:
            deserialized = self._deserialize('ApplicationResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def put(
            self, resource_group_name, cluster_name, application_name, api_version, parameters, custom_headers=None, raw=False, polling=True, **operation_config):
        """Creates or updates an application resource with the specified name.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster resource
        :type cluster_name: str
        :param application_name: The name of the application resource.
        :type application_name: str
        :param api_version: The version of the API.
        :type api_version: str
        :param parameters: The application resource.
        :type parameters: ~azure.mgmt.servicefabric.models.ApplicationResource
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns ApplicationResource or
         ClientRawResponse<ApplicationResource> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.servicefabric.models.ApplicationResource]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.servicefabric.models.ApplicationResource]]
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabric.models.ErrorModelException>`
        """
        raw_result = self._put_initial(
            resource_group_name=resource_group_name,
            cluster_name=cluster_name,
            application_name=application_name,
            api_version=api_version,
            parameters=parameters,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('ApplicationResource', response)

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
    put.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabric/clusters/{clusterName}/applications/{applicationName}'}


    def _patch_initial(
            self, resource_group_name, cluster_name, application_name, api_version, parameters, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.patch.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str'),
            'applicationName': self._serialize.url("application_name", application_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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
        body_content = self._serialize.body(parameters, 'ApplicationResourceUpdate')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [202]:
            raise models.ErrorModelException(self._deserialize, response)

        deserialized = None

        if response.status_code == 202:
            deserialized = self._deserialize('ApplicationResourceUpdate', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def patch(
            self, resource_group_name, cluster_name, application_name, api_version, parameters, custom_headers=None, raw=False, polling=True, **operation_config):
        """Updates an application resource with the specified name.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster resource
        :type cluster_name: str
        :param application_name: The name of the application resource.
        :type application_name: str
        :param api_version: The version of the API.
        :type api_version: str
        :param parameters: The application resource for patch operations.
        :type parameters:
         ~azure.mgmt.servicefabric.models.ApplicationResourceUpdate
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns
         ApplicationResourceUpdate or
         ClientRawResponse<ApplicationResourceUpdate> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.servicefabric.models.ApplicationResourceUpdate]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.servicefabric.models.ApplicationResourceUpdate]]
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabric.models.ErrorModelException>`
        """
        raw_result = self._patch_initial(
            resource_group_name=resource_group_name,
            cluster_name=cluster_name,
            application_name=application_name,
            api_version=api_version,
            parameters=parameters,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('ApplicationResourceUpdate', response)

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
    patch.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabric/clusters/{clusterName}/applications/{applicationName}'}


    def _delete_initial(
            self, resource_group_name, cluster_name, application_name, api_version, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str'),
            'applicationName': self._serialize.url("application_name", application_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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

        if response.status_code not in [202, 204]:
            raise models.ErrorModelException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def delete(
            self, resource_group_name, cluster_name, application_name, api_version, custom_headers=None, raw=False, polling=True, **operation_config):
        """Deletes an application resource with the specified name.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster resource
        :type cluster_name: str
        :param application_name: The name of the application resource.
        :type application_name: str
        :param api_version: The version of the API.
        :type api_version: str
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
         :class:`ErrorModelException<azure.mgmt.servicefabric.models.ErrorModelException>`
        """
        raw_result = self._delete_initial(
            resource_group_name=resource_group_name,
            cluster_name=cluster_name,
            application_name=application_name,
            api_version=api_version,
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
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabric/clusters/{clusterName}/applications/{applicationName}'}

    def list(
            self, resource_group_name, cluster_name, api_version, custom_headers=None, raw=False, **operation_config):
        """Returns all application resources in the specified cluster.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param cluster_name: The name of the cluster resource
        :type cluster_name: str
        :param api_version: The version of the API.
        :type api_version: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ApplicationResourceList or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.servicefabric.models.ApplicationResourceList or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabric.models.ErrorModelException>`
        """
        # Construct URL
        url = self.list.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'clusterName': self._serialize.url("cluster_name", cluster_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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
            raise models.ErrorModelException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ApplicationResourceList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabric/clusters/{clusterName}/applications'}
