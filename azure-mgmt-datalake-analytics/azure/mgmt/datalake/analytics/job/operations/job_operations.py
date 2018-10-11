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


class JobOperations(object):
    """JobOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2017-09-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-09-01-preview"

        self.config = config

    def list(
            self, account_name, filter=None, top=None, skip=None, select=None, orderby=None, count=None, custom_headers=None, raw=False, **operation_config):
        """Lists the jobs, if any, associated with the specified Data Lake
        Analytics account. The response includes a link to the next page of
        results, if any.

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param filter: OData filter. Optional.
        :type filter: str
        :param top: The number of items to return. Optional.
        :type top: int
        :param skip: The number of items to skip over before returning
         elements. Optional.
        :type skip: int
        :param select: OData Select statement. Limits the properties on each
         entry to just those requested, e.g.
         Categories?$select=CategoryName,Description. Optional.
        :type select: str
        :param orderby: OrderBy clause. One or more comma-separated
         expressions with an optional "asc" (the default) or "desc" depending
         on the order you'd like the values sorted, e.g.
         Categories?$orderby=CategoryName desc. Optional.
        :type orderby: str
        :param count: The Boolean value of true or false to request a count of
         the matching resources included with the resources in the response,
         e.g. Categories?$count=true. Optional.
        :type count: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of JobInformationBasic
        :rtype:
         ~azure.mgmt.datalake.analytics.job.models.JobInformationBasicPaged[~azure.mgmt.datalake.analytics.job.models.JobInformationBasic]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
                    'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True)
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', minimum=1)
                if skip is not None:
                    query_parameters['$skip'] = self._serialize.query("skip", skip, 'int', minimum=1)
                if select is not None:
                    query_parameters['$select'] = self._serialize.query("select", select, 'str')
                if orderby is not None:
                    query_parameters['$orderby'] = self._serialize.query("orderby", orderby, 'str')
                if count is not None:
                    query_parameters['$count'] = self._serialize.query("count", count, 'bool')
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
        deserialized = models.JobInformationBasicPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.JobInformationBasicPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/jobs'}

    def create(
            self, account_name, job_identity, parameters, custom_headers=None, raw=False, **operation_config):
        """Submits a job to the specified Data Lake Analytics account.

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param job_identity: Job identifier. Uniquely identifies the job
         across all jobs submitted to the service.
        :type job_identity: str
        :param parameters: The parameters to submit a job.
        :type parameters:
         ~azure.mgmt.datalake.analytics.job.models.CreateJobParameters
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: JobInformation or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datalake.analytics.job.models.JobInformation or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
            'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True),
            'jobIdentity': self._serialize.url("job_identity", job_identity, 'str')
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
        body_content = self._serialize.body(parameters, 'CreateJobParameters')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('JobInformation', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create.metadata = {'url': '/jobs/{jobIdentity}'}

    def get(
            self, account_name, job_identity, custom_headers=None, raw=False, **operation_config):
        """Gets the job information for the specified job ID.

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param job_identity: JobInfo ID.
        :type job_identity: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: JobInformation or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datalake.analytics.job.models.JobInformation or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
            'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True),
            'jobIdentity': self._serialize.url("job_identity", job_identity, 'str')
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
            deserialized = self._deserialize('JobInformation', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/jobs/{jobIdentity}'}


    def _update_initial(
            self, account_name, job_identity, parameters=None, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
            'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True),
            'jobIdentity': self._serialize.url("job_identity", job_identity, 'str')
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
        if parameters is not None:
            body_content = self._serialize.body(parameters, 'UpdateJobParameters')
        else:
            body_content = None

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201, 202]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('JobInformation', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def update(
            self, account_name, job_identity, parameters=None, custom_headers=None, raw=False, polling=True, **operation_config):
        """Updates the job information for the specified job ID. (Only for use
        internally with Scope job type.).

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param job_identity: Job identifier. Uniquely identifies the job
         across all jobs submitted to the service.
        :type job_identity: str
        :param parameters: The parameters to update a job.
        :type parameters:
         ~azure.mgmt.datalake.analytics.job.models.UpdateJobParameters
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns JobInformation or
         ClientRawResponse<JobInformation> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.datalake.analytics.job.models.JobInformation]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.datalake.analytics.job.models.JobInformation]]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._update_initial(
            account_name=account_name,
            job_identity=job_identity,
            parameters=parameters,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('JobInformation', response)

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
    update.metadata = {'url': '/jobs/{jobIdentity}'}

    def get_statistics(
            self, account_name, job_identity, custom_headers=None, raw=False, **operation_config):
        """Gets statistics of the specified job.

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param job_identity: Job Information ID.
        :type job_identity: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: JobStatistics or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datalake.analytics.job.models.JobStatistics or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get_statistics.metadata['url']
        path_format_arguments = {
            'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
            'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True),
            'jobIdentity': self._serialize.url("job_identity", job_identity, 'str')
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
            deserialized = self._deserialize('JobStatistics', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_statistics.metadata = {'url': '/jobs/{jobIdentity}/GetStatistics'}

    def get_debug_data_path(
            self, account_name, job_identity, custom_headers=None, raw=False, **operation_config):
        """Gets the job debug data information specified by the job ID.

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param job_identity: Job identifier. Uniquely identifies the job
         across all jobs submitted to the service.
        :type job_identity: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: JobDataPath or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datalake.analytics.job.models.JobDataPath or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get_debug_data_path.metadata['url']
        path_format_arguments = {
            'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
            'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True),
            'jobIdentity': self._serialize.url("job_identity", job_identity, 'str')
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
            deserialized = self._deserialize('JobDataPath', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_debug_data_path.metadata = {'url': '/jobs/{jobIdentity}/GetDebugDataPath'}


    def _cancel_initial(
            self, account_name, job_identity, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.cancel.metadata['url']
        path_format_arguments = {
            'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
            'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True),
            'jobIdentity': self._serialize.url("job_identity", job_identity, 'str')
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
        request = self._client.post(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def cancel(
            self, account_name, job_identity, custom_headers=None, raw=False, polling=True, **operation_config):
        """Cancels the running job specified by the job ID.

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param job_identity: Job identifier. Uniquely identifies the job
         across all jobs submitted to the service.
        :type job_identity: str
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
        raw_result = self._cancel_initial(
            account_name=account_name,
            job_identity=job_identity,
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
    cancel.metadata = {'url': '/jobs/{jobIdentity}/CancelJob'}


    def _yield_method_initial(
            self, account_name, job_identity, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.yield_method.metadata['url']
        path_format_arguments = {
            'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
            'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True),
            'jobIdentity': self._serialize.url("job_identity", job_identity, 'str')
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
        request = self._client.post(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def yield_method(
            self, account_name, job_identity, custom_headers=None, raw=False, polling=True, **operation_config):
        """Pauses the specified job and places it back in the job queue, behind
        other jobs of equal or higher importance, based on priority. (Only for
        use internally with Scope job type.).

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param job_identity: Job identifier. Uniquely identifies the job
         across all jobs submitted to the service.
        :type job_identity: str
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
        raw_result = self._yield_method_initial(
            account_name=account_name,
            job_identity=job_identity,
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
    yield_method.metadata = {'url': '/jobs/{jobIdentity}/YieldJob'}

    def build(
            self, account_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Builds (compiles) the specified job in the specified Data Lake
        Analytics account for job correctness and validation.

        :param account_name: The Azure Data Lake Analytics account to execute
         job operations on.
        :type account_name: str
        :param parameters: The parameters to build a job.
        :type parameters:
         ~azure.mgmt.datalake.analytics.job.models.BuildJobParameters
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: JobInformation or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.datalake.analytics.job.models.JobInformation or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.build.metadata['url']
        path_format_arguments = {
            'accountName': self._serialize.url("account_name", account_name, 'str', skip_quote=True),
            'adlaJobDnsSuffix': self._serialize.url("self.config.adla_job_dns_suffix", self.config.adla_job_dns_suffix, 'str', skip_quote=True)
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
        body_content = self._serialize.body(parameters, 'BuildJobParameters')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('JobInformation', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    build.metadata = {'url': '/buildJob'}
