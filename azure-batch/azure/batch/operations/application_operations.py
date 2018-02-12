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


class ApplicationOperations(object):
    """ApplicationOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    :ivar api_version: Client API Version. Constant value: "2017-09-01.6.0".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-09-01.6.0"

        self.config = config

    def list(
            self, application_list_options=None, custom_headers=None, raw=False, **operation_config):
        """Lists all of the applications available in the specified account.

        This operation returns only applications and versions that are
        available for use on compute nodes; that is, that can be used in an
        application package reference. For administrator information about
        applications and versions that are not yet available to compute nodes,
        use the Azure portal or the Azure Resource Manager API.

        :param application_list_options: Additional parameters for the
         operation
        :type application_list_options:
         ~azure.batch.models.ApplicationListOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ApplicationSummary
        :rtype:
         ~azure.batch.models.ApplicationSummaryPaged[~azure.batch.models.ApplicationSummary]
        :raises:
         :class:`BatchErrorException<azure.batch.models.BatchErrorException>`
        """
        max_results = None
        if application_list_options is not None:
            max_results = application_list_options.max_results
        timeout = None
        if application_list_options is not None:
            timeout = application_list_options.timeout
        client_request_id = None
        if application_list_options is not None:
            client_request_id = application_list_options.client_request_id
        return_client_request_id = None
        if application_list_options is not None:
            return_client_request_id = application_list_options.return_client_request_id
        ocp_date = None
        if application_list_options is not None:
            ocp_date = application_list_options.ocp_date

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/applications'

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if max_results is not None:
                    query_parameters['maxresults'] = self._serialize.query("max_results", max_results, 'int', maximum=1000, minimum=1)
                if timeout is not None:
                    query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Content-Type'] = 'application/json; charset=utf-8'
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
            request = self._client.get(url, query_parameters)
            response = self._client.send(
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.BatchErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.ApplicationSummaryPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.ApplicationSummaryPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized

    def get(
            self, application_id, application_get_options=None, custom_headers=None, raw=False, **operation_config):
        """Gets information about the specified application.

        This operation returns only applications and versions that are
        available for use on compute nodes; that is, that can be used in an
        application package reference. For administrator information about
        applications and versions that are not yet available to compute nodes,
        use the Azure portal or the Azure Resource Manager API.

        :param application_id: The ID of the application.
        :type application_id: str
        :param application_get_options: Additional parameters for the
         operation
        :type application_get_options:
         ~azure.batch.models.ApplicationGetOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ApplicationSummary or ClientRawResponse if raw=true
        :rtype: ~azure.batch.models.ApplicationSummary or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`BatchErrorException<azure.batch.models.BatchErrorException>`
        """
        timeout = None
        if application_get_options is not None:
            timeout = application_get_options.timeout
        client_request_id = None
        if application_get_options is not None:
            client_request_id = application_get_options.client_request_id
        return_client_request_id = None
        if application_get_options is not None:
            return_client_request_id = application_get_options.return_client_request_id
        ocp_date = None
        if application_get_options is not None:
            ocp_date = application_get_options.ocp_date

        # Construct URL
        url = '/applications/{applicationId}'
        path_format_arguments = {
            'applicationId': self._serialize.url("application_id", application_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
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
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.BatchErrorException(self._deserialize, response)

        deserialized = None
        header_dict = {}

        if response.status_code == 200:
            deserialized = self._deserialize('ApplicationSummary', response)
            header_dict = {
                'client-request-id': 'str',
                'request-id': 'str',
                'ETag': 'str',
                'Last-Modified': 'rfc-1123',
            }

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            client_raw_response.add_headers(header_dict)
            return client_raw_response

        return deserialized
