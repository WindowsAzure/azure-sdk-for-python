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
from msrestazure.azure_operation import AzureOperationPoller

from .. import models


class ManagedDatabasesOperations(object):
    """ManagedDatabasesOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    :ivar api_version: The API version to use for the request. Constant value: "2017-03-01-preview".
    """

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-03-01-preview"

        self.config = config

    def complete_restore(
            self, location_name, operation_id, last_backup_name, custom_headers=None, raw=False, **operation_config):
        """Completes the restore operation on a managed database.

        :param location_name: The name of the region where the resource is
         located.
        :type location_name: str
        :param operation_id: Management operation id that this request tries
         to complete.
        :type operation_id: str
        :param last_backup_name: The last backup name to apply
        :type last_backup_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns None or
         ClientRawResponse if raw=true
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`ErrorException<azure.mgmt.sql.models.ErrorException>`
        """
        parameters = models.CompleteManagedDatabaseRestoreDefinition(last_backup_name=last_backup_name)

        # Construct URL
        url = '/subscriptions/{subscriptionId}/providers/Microsoft.Sql/locations/{locationName}/managedDatabaseRestoreAzureAsyncOperation/{operationId}/completeRestore'
        path_format_arguments = {
            'locationName': self._serialize.url("location_name", location_name, 'str'),
            'operationId': self._serialize.url("operation_id", operation_id, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        body_content = self._serialize.body(parameters, 'CompleteManagedDatabaseRestoreDefinition')

        # Construct and send request
        def long_running_send():

            request = self._client.post(url, query_parameters)
            return self._client.send(
                request, header_parameters, body_content, **operation_config)

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 202]:
                raise models.ErrorException(self._deserialize, response)

            if raw:
                client_raw_response = ClientRawResponse(None, response)
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

    def list_by_instance(
            self, resource_group_name, managed_instance_name, custom_headers=None, raw=False, **operation_config):
        """Gets a list of managed databases.

        :param resource_group_name: The name of the resource group that
         contains the resource. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ManagedDatabase
        :rtype:
         ~azure.mgmt.sql.models.ManagedDatabasePaged[~azure.mgmt.sql.models.ManagedDatabase]
        :raises: :class:`ErrorException<azure.mgmt.sql.models.ErrorException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases'
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
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
                raise models.ErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.ManagedDatabasePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.ManagedDatabasePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized

    def get(
            self, resource_group_name, managed_instance_name, database_name, custom_headers=None, raw=False, **operation_config):
        """Gets a managed database.

        :param resource_group_name: The name of the resource group that
         contains the resource. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ManagedDatabase or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.sql.models.ManagedDatabase or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`ErrorException<azure.mgmt.sql.models.ErrorException>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}'
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ManagedDatabase', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create_or_update(
            self, resource_group_name, managed_instance_name, database_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Creates a new database or updates an existing database.

        :param resource_group_name: The name of the resource group that
         contains the resource. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param parameters: The requested database resource state.
        :type parameters: ~azure.mgmt.sql.models.ManagedDatabase
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns
         ManagedDatabase or ClientRawResponse if raw=true
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.sql.models.ManagedDatabase]
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`ErrorException<azure.mgmt.sql.models.ErrorException>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}'
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        body_content = self._serialize.body(parameters, 'ManagedDatabase')

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

            if response.status_code not in [200, 202, 201]:
                raise models.ErrorException(self._deserialize, response)

            deserialized = None

            if response.status_code == 200:
                deserialized = self._deserialize('ManagedDatabase', response)
            if response.status_code == 201:
                deserialized = self._deserialize('ManagedDatabase', response)

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

    def delete(
            self, resource_group_name, managed_instance_name, database_name, custom_headers=None, raw=False, **operation_config):
        """Deletes the managed database.

        :param resource_group_name: The name of the resource group that
         contains the resource. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns None or
         ClientRawResponse if raw=true
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`ErrorException<azure.mgmt.sql.models.ErrorException>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}'
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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

            request = self._client.delete(url, query_parameters)
            return self._client.send(request, header_parameters, **operation_config)

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 202, 204]:
                raise models.ErrorException(self._deserialize, response)

            if raw:
                client_raw_response = ClientRawResponse(None, response)
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

    def update(
            self, resource_group_name, managed_instance_name, database_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Updates an existing database.

        :param resource_group_name: The name of the resource group that
         contains the resource. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param parameters: The requested database resource state.
        :type parameters: ~azure.mgmt.sql.models.ManagedDatabaseUpdate
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns
         ManagedDatabase or ClientRawResponse if raw=true
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.sql.models.ManagedDatabase]
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`ErrorException<azure.mgmt.sql.models.ErrorException>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}'
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        body_content = self._serialize.body(parameters, 'ManagedDatabaseUpdate')

        # Construct and send request
        def long_running_send():

            request = self._client.patch(url, query_parameters)
            return self._client.send(
                request, header_parameters, body_content, **operation_config)

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 202]:
                raise models.ErrorException(self._deserialize, response)

            deserialized = None

            if response.status_code == 200:
                deserialized = self._deserialize('ManagedDatabase', response)

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
