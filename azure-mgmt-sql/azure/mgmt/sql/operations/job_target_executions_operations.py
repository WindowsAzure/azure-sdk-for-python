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


class JobTargetExecutionsOperations(object):
    """JobTargetExecutionsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: The API version to use for the request. Constant value: "2017-03-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-03-01-preview"

        self.config = config

    def list_by_job_execution(
            self, resource_group_name, server_name, job_agent_name, job_name, job_execution_id, create_time_min=None, create_time_max=None, end_time_min=None, end_time_max=None, is_active=None, skip=None, top=None, custom_headers=None, raw=False, **operation_config):
        """Lists target executions for all steps of a job execution.

        :param resource_group_name: The name of the resource group that
         contains the resource. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param server_name: The name of the server.
        :type server_name: str
        :param job_agent_name: The name of the job agent.
        :type job_agent_name: str
        :param job_name: The name of the job to get.
        :type job_name: str
        :param job_execution_id: The id of the job execution
        :type job_execution_id: str
        :param create_time_min: If specified, only job executions created at
         or after the specified time are included.
        :type create_time_min: datetime
        :param create_time_max: If specified, only job executions created
         before the specified time are included.
        :type create_time_max: datetime
        :param end_time_min: If specified, only job executions completed at or
         after the specified time are included.
        :type end_time_min: datetime
        :param end_time_max: If specified, only job executions completed
         before the specified time are included.
        :type end_time_max: datetime
        :param is_active: If specified, only active or only completed job
         executions are included.
        :type is_active: bool
        :param skip: The number of elements in the collection to skip.
        :type skip: int
        :param top: The number of elements to return from the collection.
        :type top: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of JobExecution
        :rtype:
         ~azure.mgmt.sql.models.JobExecutionPaged[~azure.mgmt.sql.models.JobExecution]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_job_execution.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'serverName': self._serialize.url("server_name", server_name, 'str'),
                    'jobAgentName': self._serialize.url("job_agent_name", job_agent_name, 'str'),
                    'jobName': self._serialize.url("job_name", job_name, 'str'),
                    'jobExecutionId': self._serialize.url("job_execution_id", job_execution_id, 'str'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if create_time_min is not None:
                    query_parameters['createTimeMin'] = self._serialize.query("create_time_min", create_time_min, 'iso-8601')
                if create_time_max is not None:
                    query_parameters['createTimeMax'] = self._serialize.query("create_time_max", create_time_max, 'iso-8601')
                if end_time_min is not None:
                    query_parameters['endTimeMin'] = self._serialize.query("end_time_min", end_time_min, 'iso-8601')
                if end_time_max is not None:
                    query_parameters['endTimeMax'] = self._serialize.query("end_time_max", end_time_max, 'iso-8601')
                if is_active is not None:
                    query_parameters['isActive'] = self._serialize.query("is_active", is_active, 'bool')
                if skip is not None:
                    query_parameters['$skip'] = self._serialize.query("skip", skip, 'int')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
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
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.JobExecutionPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.JobExecutionPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_job_execution.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/jobAgents/{jobAgentName}/jobs/{jobName}/executions/{jobExecutionId}/targets'}

    def list_by_step(
            self, resource_group_name, server_name, job_agent_name, job_name, job_execution_id, step_name, create_time_min=None, create_time_max=None, end_time_min=None, end_time_max=None, is_active=None, skip=None, top=None, custom_headers=None, raw=False, **operation_config):
        """Lists the target executions of a job step execution.

        :param resource_group_name: The name of the resource group that
         contains the resource. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param server_name: The name of the server.
        :type server_name: str
        :param job_agent_name: The name of the job agent.
        :type job_agent_name: str
        :param job_name: The name of the job to get.
        :type job_name: str
        :param job_execution_id: The id of the job execution
        :type job_execution_id: str
        :param step_name: The name of the step.
        :type step_name: str
        :param create_time_min: If specified, only job executions created at
         or after the specified time are included.
        :type create_time_min: datetime
        :param create_time_max: If specified, only job executions created
         before the specified time are included.
        :type create_time_max: datetime
        :param end_time_min: If specified, only job executions completed at or
         after the specified time are included.
        :type end_time_min: datetime
        :param end_time_max: If specified, only job executions completed
         before the specified time are included.
        :type end_time_max: datetime
        :param is_active: If specified, only active or only completed job
         executions are included.
        :type is_active: bool
        :param skip: The number of elements in the collection to skip.
        :type skip: int
        :param top: The number of elements to return from the collection.
        :type top: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of JobExecution
        :rtype:
         ~azure.mgmt.sql.models.JobExecutionPaged[~azure.mgmt.sql.models.JobExecution]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_step.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'serverName': self._serialize.url("server_name", server_name, 'str'),
                    'jobAgentName': self._serialize.url("job_agent_name", job_agent_name, 'str'),
                    'jobName': self._serialize.url("job_name", job_name, 'str'),
                    'jobExecutionId': self._serialize.url("job_execution_id", job_execution_id, 'str'),
                    'stepName': self._serialize.url("step_name", step_name, 'str'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if create_time_min is not None:
                    query_parameters['createTimeMin'] = self._serialize.query("create_time_min", create_time_min, 'iso-8601')
                if create_time_max is not None:
                    query_parameters['createTimeMax'] = self._serialize.query("create_time_max", create_time_max, 'iso-8601')
                if end_time_min is not None:
                    query_parameters['endTimeMin'] = self._serialize.query("end_time_min", end_time_min, 'iso-8601')
                if end_time_max is not None:
                    query_parameters['endTimeMax'] = self._serialize.query("end_time_max", end_time_max, 'iso-8601')
                if is_active is not None:
                    query_parameters['isActive'] = self._serialize.query("is_active", is_active, 'bool')
                if skip is not None:
                    query_parameters['$skip'] = self._serialize.query("skip", skip, 'int')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
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
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.JobExecutionPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.JobExecutionPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_step.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/jobAgents/{jobAgentName}/jobs/{jobName}/executions/{jobExecutionId}/steps/{stepName}/targets'}

    def get(
            self, resource_group_name, server_name, job_agent_name, job_name, job_execution_id, step_name, target_id, custom_headers=None, raw=False, **operation_config):
        """Gets a target execution.

        :param resource_group_name: The name of the resource group that
         contains the resource. You can obtain this value from the Azure
         Resource Manager API or the portal.
        :type resource_group_name: str
        :param server_name: The name of the server.
        :type server_name: str
        :param job_agent_name: The name of the job agent.
        :type job_agent_name: str
        :param job_name: The name of the job to get.
        :type job_name: str
        :param job_execution_id: The unique id of the job execution
        :type job_execution_id: str
        :param step_name: The name of the step.
        :type step_name: str
        :param target_id: The target id.
        :type target_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: JobExecution or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.sql.models.JobExecution or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'serverName': self._serialize.url("server_name", server_name, 'str'),
            'jobAgentName': self._serialize.url("job_agent_name", job_agent_name, 'str'),
            'jobName': self._serialize.url("job_name", job_name, 'str'),
            'jobExecutionId': self._serialize.url("job_execution_id", job_execution_id, 'str'),
            'stepName': self._serialize.url("step_name", step_name, 'str'),
            'targetId': self._serialize.url("target_id", target_id, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('JobExecution', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/jobAgents/{jobAgentName}/jobs/{jobName}/executions/{jobExecutionId}/steps/{stepName}/targets/{targetId}'}
