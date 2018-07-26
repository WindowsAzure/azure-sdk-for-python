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
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling

from .. import models


class JobsOperations(object):
    """JobsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Specifies the version of API used for this request. Constant value: "2018-05-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-05-01"

        self.config = config

    def list_by_experiment(
            self, resource_group_name, workspace_name, experiment_name, jobs_list_by_experiment_options=None, custom_headers=None, raw=False, **operation_config):
        """Gets a list of Jobs within the specified Experiment.

        :param resource_group_name: Name of the resource group to which the
         resource belongs.
        :type resource_group_name: str
        :param workspace_name: The name of the workspace. Workspace names can
         only contain a combination of alphanumeric characters along with dash
         (-) and underscore (_). The name must be from 1 through 64 characters
         long.
        :type workspace_name: str
        :param experiment_name: The name of the experiment. Experiment names
         can only contain a combination of alphanumeric characters along with
         dash (-) and underscore (_). The name must be from 1 through 64
         characters long.
        :type experiment_name: str
        :param jobs_list_by_experiment_options: Additional parameters for the
         operation
        :type jobs_list_by_experiment_options:
         ~azure.mgmt.batchai.models.JobsListByExperimentOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Job
        :rtype:
         ~azure.mgmt.batchai.models.JobPaged[~azure.mgmt.batchai.models.Job]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        max_results = None
        if jobs_list_by_experiment_options is not None:
            max_results = jobs_list_by_experiment_options.max_results

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_experiment.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', pattern=r'^[-\w\._]+$'),
                    'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
                    'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if max_results is not None:
                    query_parameters['maxresults'] = self._serialize.query("max_results", max_results, 'int', maximum=1000, minimum=1)

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
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.JobPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.JobPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_experiment.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BatchAI/workspaces/{workspaceName}/experiments/{experimentName}/jobs'}


    def _create_initial(
            self, resource_group_name, workspace_name, experiment_name, job_name, parameters, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', pattern=r'^[-\w\._]+$'),
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
            'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
            'jobName': self._serialize.url("job_name", job_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
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
        body_content = self._serialize.body(parameters, 'JobCreateParameters')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Job', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create(
            self, resource_group_name, workspace_name, experiment_name, job_name, parameters, custom_headers=None, raw=False, polling=True, **operation_config):
        """Creates a Job in the given Experiment.

        :param resource_group_name: Name of the resource group to which the
         resource belongs.
        :type resource_group_name: str
        :param workspace_name: The name of the workspace. Workspace names can
         only contain a combination of alphanumeric characters along with dash
         (-) and underscore (_). The name must be from 1 through 64 characters
         long.
        :type workspace_name: str
        :param experiment_name: The name of the experiment. Experiment names
         can only contain a combination of alphanumeric characters along with
         dash (-) and underscore (_). The name must be from 1 through 64
         characters long.
        :type experiment_name: str
        :param job_name: The name of the job within the specified resource
         group. Job names can only contain a combination of alphanumeric
         characters along with dash (-) and underscore (_). The name must be
         from 1 through 64 characters long.
        :type job_name: str
        :param parameters: The parameters to provide for job creation.
        :type parameters: ~azure.mgmt.batchai.models.JobCreateParameters
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns Job or
         ClientRawResponse<Job> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.batchai.models.Job]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.batchai.models.Job]]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._create_initial(
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
            experiment_name=experiment_name,
            job_name=job_name,
            parameters=parameters,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('Job', response)

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
    create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BatchAI/workspaces/{workspaceName}/experiments/{experimentName}/jobs/{jobName}'}


    def _delete_initial(
            self, resource_group_name, workspace_name, experiment_name, job_name, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', pattern=r'^[-\w\._]+$'),
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
            'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
            'jobName': self._serialize.url("job_name", job_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
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
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200, 202, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def delete(
            self, resource_group_name, workspace_name, experiment_name, job_name, custom_headers=None, raw=False, polling=True, **operation_config):
        """Deletes a Job.

        :param resource_group_name: Name of the resource group to which the
         resource belongs.
        :type resource_group_name: str
        :param workspace_name: The name of the workspace. Workspace names can
         only contain a combination of alphanumeric characters along with dash
         (-) and underscore (_). The name must be from 1 through 64 characters
         long.
        :type workspace_name: str
        :param experiment_name: The name of the experiment. Experiment names
         can only contain a combination of alphanumeric characters along with
         dash (-) and underscore (_). The name must be from 1 through 64
         characters long.
        :type experiment_name: str
        :param job_name: The name of the job within the specified resource
         group. Job names can only contain a combination of alphanumeric
         characters along with dash (-) and underscore (_). The name must be
         from 1 through 64 characters long.
        :type job_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns None or
         ClientRawResponse<None> if raw==True
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[None]]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._delete_initial(
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
            experiment_name=experiment_name,
            job_name=job_name,
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
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BatchAI/workspaces/{workspaceName}/experiments/{experimentName}/jobs/{jobName}'}

    def get(
            self, resource_group_name, workspace_name, experiment_name, job_name, custom_headers=None, raw=False, **operation_config):
        """Gets information about a Job.

        :param resource_group_name: Name of the resource group to which the
         resource belongs.
        :type resource_group_name: str
        :param workspace_name: The name of the workspace. Workspace names can
         only contain a combination of alphanumeric characters along with dash
         (-) and underscore (_). The name must be from 1 through 64 characters
         long.
        :type workspace_name: str
        :param experiment_name: The name of the experiment. Experiment names
         can only contain a combination of alphanumeric characters along with
         dash (-) and underscore (_). The name must be from 1 through 64
         characters long.
        :type experiment_name: str
        :param job_name: The name of the job within the specified resource
         group. Job names can only contain a combination of alphanumeric
         characters along with dash (-) and underscore (_). The name must be
         from 1 through 64 characters long.
        :type job_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Job or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.batchai.models.Job or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', pattern=r'^[-\w\._]+$'),
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
            'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
            'jobName': self._serialize.url("job_name", job_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
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
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Job', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BatchAI/workspaces/{workspaceName}/experiments/{experimentName}/jobs/{jobName}'}

    def list_output_files(
            self, resource_group_name, workspace_name, experiment_name, job_name, jobs_list_output_files_options, custom_headers=None, raw=False, **operation_config):
        """List all directories and files inside the given directory of the Job's
        output directory (if the output directory is on Azure File Share or
        Azure Storage Container).

        :param resource_group_name: Name of the resource group to which the
         resource belongs.
        :type resource_group_name: str
        :param workspace_name: The name of the workspace. Workspace names can
         only contain a combination of alphanumeric characters along with dash
         (-) and underscore (_). The name must be from 1 through 64 characters
         long.
        :type workspace_name: str
        :param experiment_name: The name of the experiment. Experiment names
         can only contain a combination of alphanumeric characters along with
         dash (-) and underscore (_). The name must be from 1 through 64
         characters long.
        :type experiment_name: str
        :param job_name: The name of the job within the specified resource
         group. Job names can only contain a combination of alphanumeric
         characters along with dash (-) and underscore (_). The name must be
         from 1 through 64 characters long.
        :type job_name: str
        :param jobs_list_output_files_options: Additional parameters for the
         operation
        :type jobs_list_output_files_options:
         ~azure.mgmt.batchai.models.JobsListOutputFilesOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of File
        :rtype:
         ~azure.mgmt.batchai.models.FilePaged[~azure.mgmt.batchai.models.File]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        outputdirectoryid = None
        if jobs_list_output_files_options is not None:
            outputdirectoryid = jobs_list_output_files_options.outputdirectoryid
        directory = None
        if jobs_list_output_files_options is not None:
            directory = jobs_list_output_files_options.directory
        linkexpiryinminutes = None
        if jobs_list_output_files_options is not None:
            linkexpiryinminutes = jobs_list_output_files_options.linkexpiryinminutes
        max_results = None
        if jobs_list_output_files_options is not None:
            max_results = jobs_list_output_files_options.max_results

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_output_files.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', pattern=r'^[-\w\._]+$'),
                    'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
                    'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
                    'jobName': self._serialize.url("job_name", job_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                query_parameters['outputdirectoryid'] = self._serialize.query("outputdirectoryid", outputdirectoryid, 'str')
                if directory is not None:
                    query_parameters['directory'] = self._serialize.query("directory", directory, 'str')
                if linkexpiryinminutes is not None:
                    query_parameters['linkexpiryinminutes'] = self._serialize.query("linkexpiryinminutes", linkexpiryinminutes, 'int', maximum=600, minimum=5)
                if max_results is not None:
                    query_parameters['maxresults'] = self._serialize.query("max_results", max_results, 'int', maximum=1000, minimum=1)

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
            request = self._client.post(url, query_parameters)
            response = self._client.send(
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.FilePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.FilePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_output_files.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BatchAI/workspaces/{workspaceName}/experiments/{experimentName}/jobs/{jobName}/listOutputFiles'}

    def list_remote_login_information(
            self, resource_group_name, workspace_name, experiment_name, job_name, custom_headers=None, raw=False, **operation_config):
        """Gets a list of currently existing nodes which were used for the Job
        execution. The returned information contains the node ID, its public IP
        and SSH port.

        :param resource_group_name: Name of the resource group to which the
         resource belongs.
        :type resource_group_name: str
        :param workspace_name: The name of the workspace. Workspace names can
         only contain a combination of alphanumeric characters along with dash
         (-) and underscore (_). The name must be from 1 through 64 characters
         long.
        :type workspace_name: str
        :param experiment_name: The name of the experiment. Experiment names
         can only contain a combination of alphanumeric characters along with
         dash (-) and underscore (_). The name must be from 1 through 64
         characters long.
        :type experiment_name: str
        :param job_name: The name of the job within the specified resource
         group. Job names can only contain a combination of alphanumeric
         characters along with dash (-) and underscore (_). The name must be
         from 1 through 64 characters long.
        :type job_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of RemoteLoginInformation
        :rtype:
         ~azure.mgmt.batchai.models.RemoteLoginInformationPaged[~azure.mgmt.batchai.models.RemoteLoginInformation]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_remote_login_information.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', pattern=r'^[-\w\._]+$'),
                    'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
                    'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
                    'jobName': self._serialize.url("job_name", job_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
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
            request = self._client.post(url, query_parameters)
            response = self._client.send(
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.RemoteLoginInformationPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.RemoteLoginInformationPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_remote_login_information.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BatchAI/workspaces/{workspaceName}/experiments/{experimentName}/jobs/{jobName}/listRemoteLoginInformation'}


    def _terminate_initial(
            self, resource_group_name, workspace_name, experiment_name, job_name, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.terminate.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', pattern=r'^[-\w\._]+$'),
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
            'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
            'jobName': self._serialize.url("job_name", job_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w_]+$'),
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
        request = self._client.post(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def terminate(
            self, resource_group_name, workspace_name, experiment_name, job_name, custom_headers=None, raw=False, polling=True, **operation_config):
        """Terminates a job.

        :param resource_group_name: Name of the resource group to which the
         resource belongs.
        :type resource_group_name: str
        :param workspace_name: The name of the workspace. Workspace names can
         only contain a combination of alphanumeric characters along with dash
         (-) and underscore (_). The name must be from 1 through 64 characters
         long.
        :type workspace_name: str
        :param experiment_name: The name of the experiment. Experiment names
         can only contain a combination of alphanumeric characters along with
         dash (-) and underscore (_). The name must be from 1 through 64
         characters long.
        :type experiment_name: str
        :param job_name: The name of the job within the specified resource
         group. Job names can only contain a combination of alphanumeric
         characters along with dash (-) and underscore (_). The name must be
         from 1 through 64 characters long.
        :type job_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns None or
         ClientRawResponse<None> if raw==True
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[None]]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._terminate_initial(
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
            experiment_name=experiment_name,
            job_name=job_name,
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
    terminate.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BatchAI/workspaces/{workspaceName}/experiments/{experimentName}/jobs/{jobName}/terminate'}
