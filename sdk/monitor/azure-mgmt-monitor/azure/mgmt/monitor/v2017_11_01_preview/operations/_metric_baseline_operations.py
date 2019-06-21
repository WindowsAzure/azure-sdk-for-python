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


class MetricBaselineOperations(object):
    """MetricBaselineOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2017-11-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-11-01-preview"

        self.config = config

    def get(
            self, resource_uri, metric_name, timespan=None, interval=None, aggregation=None, sensitivities=None, result_type=None, custom_headers=None, raw=False, **operation_config):
        """**Gets the baseline values for a specific metric**.

        :param resource_uri: The identifier of the resource. It has the
         following structure:
         subscriptions/{subscriptionName}/resourceGroups/{resourceGroupName}/providers/{providerName}/{resourceName}.
         For example:
         subscriptions/b368ca2f-e298-46b7-b0ab-012281956afa/resourceGroups/vms/providers/Microsoft.Compute/virtualMachines/vm1
        :type resource_uri: str
        :param metric_name: The name of the metric to retrieve the baseline
         for.
        :type metric_name: str
        :param timespan: The timespan of the query. It is a string with the
         following format 'startDateTime_ISO/endDateTime_ISO'.
        :type timespan: str
        :param interval: The interval (i.e. timegrain) of the query.
        :type interval: timedelta
        :param aggregation: The aggregation type of the metric to retrieve the
         baseline for.
        :type aggregation: str
        :param sensitivities: The list of sensitivities (comma separated) to
         retrieve.
        :type sensitivities: str
        :param result_type: Allows retrieving only metadata of the baseline.
         On data request all information is retrieved. Possible values include:
         'Data', 'Metadata'
        :type result_type: str or
         ~azure.mgmt.monitor.v2017_11_01_preview.models.ResultType
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: BaselineResponse or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.monitor.v2017_11_01_preview.models.BaselineResponse or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.monitor.v2017_11_01_preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True),
            'metricName': self._serialize.url("metric_name", metric_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timespan is not None:
            query_parameters['timespan'] = self._serialize.query("timespan", timespan, 'str')
        if interval is not None:
            query_parameters['interval'] = self._serialize.query("interval", interval, 'duration')
        if aggregation is not None:
            query_parameters['aggregation'] = self._serialize.query("aggregation", aggregation, 'str')
        if sensitivities is not None:
            query_parameters['sensitivities'] = self._serialize.query("sensitivities", sensitivities, 'str')
        if result_type is not None:
            query_parameters['resultType'] = self._serialize.query("result_type", result_type, 'ResultType')
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
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('BaselineResponse', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/{resourceUri}/providers/microsoft.insights/baseline/{metricName}'}

    def calculate_baseline(
            self, resource_uri, time_series_information, custom_headers=None, raw=False, **operation_config):
        """**Lists the baseline values for a resource**.

        :param resource_uri: The identifier of the resource. It has the
         following structure:
         subscriptions/{subscriptionName}/resourceGroups/{resourceGroupName}/providers/{providerName}/{resourceName}.
         For example:
         subscriptions/b368ca2f-e298-46b7-b0ab-012281956afa/resourceGroups/vms/providers/Microsoft.Compute/virtualMachines/vm1
        :type resource_uri: str
        :param time_series_information: Information that need to be specified
         to calculate a baseline on a time series.
        :type time_series_information:
         ~azure.mgmt.monitor.v2017_11_01_preview.models.TimeSeriesInformation
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: CalculateBaselineResponse or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.monitor.v2017_11_01_preview.models.CalculateBaselineResponse
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.monitor.v2017_11_01_preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.calculate_baseline.metadata['url']
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True)
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
        body_content = self._serialize.body(time_series_information, 'TimeSeriesInformation')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('CalculateBaselineResponse', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    calculate_baseline.metadata = {'url': '/{resourceUri}/providers/microsoft.insights/calculatebaseline'}
