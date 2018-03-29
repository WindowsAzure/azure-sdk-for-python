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


class ProjectsOperations(object):
    """ProjectsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API. Constant value: "2018-03-31-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-03-31-preview"

        self.config = config

    def list(
            self, group_name, service_name, custom_headers=None, raw=False, **operation_config):
        """Get projects in a service.

        The project resource is a nested resource representing a stored
        migration project. This method returns a list of projects owned by a
        service resource.

        :param group_name: Name of the resource group
        :type group_name: str
        :param service_name: Name of the service
        :type service_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Project
        :rtype:
         ~azure.mgmt.datamigration.models.ProjectPaged[~azure.mgmt.datamigration.models.Project]
        :raises:
         :class:`ApiErrorException<azure.mgmt.datamigration.models.ApiErrorException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'groupName': self._serialize.url("group_name", group_name, 'str'),
                    'serviceName': self._serialize.url("service_name", service_name, 'str')
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
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ApiErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.ProjectPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.ProjectPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{groupName}/providers/Microsoft.DataMigration/services/{serviceName}/projects'}

    def create_or_update(
            self, parameters, group_name, service_name, project_name, custom_headers=None, raw=False, **operation_config):
        """Create or update project.

        The project resource is a nested resource representing a stored
        migration project. The PUT method creates a new project or updates an
        existing one.

        :param parameters: Information about the project
        :type parameters: ~azure.mgmt.datamigration.models.Project
        :param group_name: Name of the resource group
        :type group_name: str
        :param service_name: Name of the service
        :type service_name: str
        :param project_name: Name of the project
        :type project_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Project or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datamigration.models.Project or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ApiErrorException<azure.mgmt.datamigration.models.ApiErrorException>`
        """
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'groupName': self._serialize.url("group_name", group_name, 'str'),
            'serviceName': self._serialize.url("service_name", service_name, 'str'),
            'projectName': self._serialize.url("project_name", project_name, 'str')
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
        body_content = self._serialize.body(parameters, 'Project')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ApiErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Project', response)
        if response.status_code == 201:
            deserialized = self._deserialize('Project', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{groupName}/providers/Microsoft.DataMigration/services/{serviceName}/projects/{projectName}'}

    def get(
            self, group_name, service_name, project_name, custom_headers=None, raw=False, **operation_config):
        """Get project information.

        The project resource is a nested resource representing a stored
        migration project. The GET method retrieves information about a
        project.

        :param group_name: Name of the resource group
        :type group_name: str
        :param service_name: Name of the service
        :type service_name: str
        :param project_name: Name of the project
        :type project_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Project or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datamigration.models.Project or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ApiErrorException<azure.mgmt.datamigration.models.ApiErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'groupName': self._serialize.url("group_name", group_name, 'str'),
            'serviceName': self._serialize.url("service_name", service_name, 'str'),
            'projectName': self._serialize.url("project_name", project_name, 'str')
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
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ApiErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Project', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{groupName}/providers/Microsoft.DataMigration/services/{serviceName}/projects/{projectName}'}

    def delete(
            self, group_name, service_name, project_name, delete_running_tasks=None, custom_headers=None, raw=False, **operation_config):
        """Delete project.

        The project resource is a nested resource representing a stored
        migration project. The DELETE method deletes a project.

        :param group_name: Name of the resource group
        :type group_name: str
        :param service_name: Name of the service
        :type service_name: str
        :param project_name: Name of the project
        :type project_name: str
        :param delete_running_tasks: Delete the resource even if it contains
         running tasks
        :type delete_running_tasks: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ApiErrorException<azure.mgmt.datamigration.models.ApiErrorException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'groupName': self._serialize.url("group_name", group_name, 'str'),
            'serviceName': self._serialize.url("service_name", service_name, 'str'),
            'projectName': self._serialize.url("project_name", project_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if delete_running_tasks is not None:
            query_parameters['deleteRunningTasks'] = self._serialize.query("delete_running_tasks", delete_running_tasks, 'bool')
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
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200, 204]:
            raise models.ApiErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{groupName}/providers/Microsoft.DataMigration/services/{serviceName}/projects/{projectName}'}

    def update(
            self, parameters, group_name, service_name, project_name, custom_headers=None, raw=False, **operation_config):
        """Update project.

        The project resource is a nested resource representing a stored
        migration project. The PATCH method updates an existing project.

        :param parameters: Information about the project
        :type parameters: ~azure.mgmt.datamigration.models.Project
        :param group_name: Name of the resource group
        :type group_name: str
        :param service_name: Name of the service
        :type service_name: str
        :param project_name: Name of the project
        :type project_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Project or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datamigration.models.Project or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ApiErrorException<azure.mgmt.datamigration.models.ApiErrorException>`
        """
        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'groupName': self._serialize.url("group_name", group_name, 'str'),
            'serviceName': self._serialize.url("service_name", service_name, 'str'),
            'projectName': self._serialize.url("project_name", project_name, 'str')
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
        body_content = self._serialize.body(parameters, 'Project')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ApiErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Project', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{groupName}/providers/Microsoft.DataMigration/services/{serviceName}/projects/{projectName}'}
