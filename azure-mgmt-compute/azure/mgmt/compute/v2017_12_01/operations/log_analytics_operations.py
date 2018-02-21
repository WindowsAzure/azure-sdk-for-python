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
from msrest.exceptions import DeserializationError
from msrestazure.azure_operation import AzureOperationPoller

from .. import models


class LogAnalyticsOperations(object):
    """LogAnalyticsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2017-12-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-12-01"

        self.config = config


    def _export_request_rate_by_interval_initial(
            self, parameters, location, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.export_request_rate_by_interval.metadata['url']
        path_format_arguments = {
            'location': self._serialize.url("location", location, 'str', pattern=r'^[-\w\._]+$'),
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
        body_content = self._serialize.body(parameters, 'RequestRateByIntervalInput')

        # Construct and send request
        request = self._client.post(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('LogAnalyticsOperationResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def export_request_rate_by_interval(
            self, parameters, location, custom_headers=None, raw=False, **operation_config):
        """Export logs that show Api requests made by this subscription in the
        given time window to show throttling activities.

        :param parameters: Parameters supplied to the LogAnalytics
         getRequestRateByInterval Api.
        :type parameters:
         ~azure.mgmt.compute.v2017_12_01.models.RequestRateByIntervalInput
        :param location: The location upon which virtual-machine-sizes is
         queried.
        :type location: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns
         LogAnalyticsOperationResult or ClientRawResponse if raw=true
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.compute.v2017_12_01.models.LogAnalyticsOperationResult]
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._export_request_rate_by_interval_initial(
            parameters=parameters,
            location=location,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )
        if raw:
            return raw_result

        # Construct and send request
        def long_running_send():
            return raw_result.response

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            header_parameters = {}
            header_parameters['x-ms-client-request-id'] = raw_result.response.request.headers['x-ms-client-request-id']
            return self._client.send(
                request, header_parameters, stream=False, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 202]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            deserialized = self._deserialize('LogAnalyticsOperationResult', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        long_running_operation_timeout = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        return AzureOperationPoller(
            long_running_send, get_long_running_output,
            get_long_running_status, long_running_operation_timeout)
    export_request_rate_by_interval.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/logAnalytics/apiAccess/getRequestRateByInterval'}


    def _export_throttled_requests_initial(
            self, parameters, location, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.export_throttled_requests.metadata['url']
        path_format_arguments = {
            'location': self._serialize.url("location", location, 'str', pattern=r'^[-\w\._]+$'),
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
        body_content = self._serialize.body(parameters, 'ThrottledRequestsInput')

        # Construct and send request
        request = self._client.post(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('LogAnalyticsOperationResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def export_throttled_requests(
            self, parameters, location, custom_headers=None, raw=False, **operation_config):
        """Export logs that show total throttled Api requests for this
        subscription in the given time window.

        :param parameters: Parameters supplied to the LogAnalytics
         getThrottledRequests Api.
        :type parameters:
         ~azure.mgmt.compute.v2017_12_01.models.ThrottledRequestsInput
        :param location: The location upon which virtual-machine-sizes is
         queried.
        :type location: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return: An instance of AzureOperationPoller that returns
         LogAnalyticsOperationResult or ClientRawResponse if raw=true
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.compute.v2017_12_01.models.LogAnalyticsOperationResult]
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._export_throttled_requests_initial(
            parameters=parameters,
            location=location,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )
        if raw:
            return raw_result

        # Construct and send request
        def long_running_send():
            return raw_result.response

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            header_parameters = {}
            header_parameters['x-ms-client-request-id'] = raw_result.response.request.headers['x-ms-client-request-id']
            return self._client.send(
                request, header_parameters, stream=False, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 202]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            deserialized = self._deserialize('LogAnalyticsOperationResult', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        long_running_operation_timeout = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        return AzureOperationPoller(
            long_running_send, get_long_running_output,
            get_long_running_status, long_running_operation_timeout)
    export_throttled_requests.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/logAnalytics/apiAccess/getThrottledRequests'}
