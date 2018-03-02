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


class MetricsOperations(object):
    """MetricsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2018-01-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-01-01"

        self.config = config

    def list(
            self, resource_uri, timespan=None, interval=None, metricnames=None, aggregation=None, top=None, orderby=None, filter=None, result_type=None, metricnamespace=None, custom_headers=None, raw=False, **operation_config):
        """**Lists the metric values for a resource**.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :param timespan: The timespan of the query. It is a string with the
         following format 'startDateTime_ISO/endDateTime_ISO'.
        :type timespan: str
        :param interval: The interval (i.e. timegrain) of the query.
        :type interval: timedelta
        :param metricnames: The names of the metrics (comma separated) to
         retrieve.
        :type metricnames: str
        :param aggregation: The list of aggregation types (comma separated) to
         retrieve.
        :type aggregation: str
        :param top: The maximum number of records to retrieve.
         Valid only if $filter is specified.
         Defaults to 10.
        :type top: float
        :param orderby: The aggregation to use for sorting results and the
         direction of the sort.
         Only one order can be specified.
         Examples: sum asc.
        :type orderby: str
        :param filter: The **$filter** is used to reduce the set of metric
         data returned.<br>Example:<br>Metric contains metadata A, B and
         C.<br>- Return all time series of C where A = a1 and B = b1 or
         b2<br>**$filter=A eq ‘a1’ and B eq ‘b1’ or B eq ‘b2’ and C eq
         ‘*’**<br>- Invalid variant:<br>**$filter=A eq ‘a1’ and B eq ‘b1’ and C
         eq ‘*’ or B = ‘b2’**<br>This is invalid because the logical or
         operator cannot separate two different metadata names.<br>- Return all
         time series where A = a1, B = b1 and C = c1:<br>**$filter=A eq ‘a1’
         and B eq ‘b1’ and C eq ‘c1’**<br>- Return all time series where A =
         a1<br>**$filter=A eq ‘a1’ and B eq ‘*’ and C eq ‘*’**.
        :type filter: str
        :param result_type: Reduces the set of data collected. The syntax
         allowed depends on the operation. See the operation's description for
         details. Possible values include: 'Data', 'Metadata'
        :type result_type: str or ~azure.mgmt.monitor.models.ResultType
        :param metricnamespace: Metric namespace to query metric definitions
         for.
        :type metricnamespace: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Response or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.monitor.models.Response or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.monitor.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list.metadata['url']
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timespan is not None:
            query_parameters['timespan'] = self._serialize.query("timespan", timespan, 'str')
        if interval is not None:
            query_parameters['interval'] = self._serialize.query("interval", interval, 'duration')
        if metricnames is not None:
            query_parameters['metricnames'] = self._serialize.query("metricnames", metricnames, 'str')
        if aggregation is not None:
            query_parameters['aggregation'] = self._serialize.query("aggregation", aggregation, 'str')
        if top is not None:
            query_parameters['top'] = self._serialize.query("top", top, 'float')
        if orderby is not None:
            query_parameters['orderby'] = self._serialize.query("orderby", orderby, 'str')
        if filter is not None:
            query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
        if result_type is not None:
            query_parameters['resultType'] = self._serialize.query("result_type", result_type, 'ResultType')
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
        if metricnamespace is not None:
            query_parameters['metricnamespace'] = self._serialize.query("metricnamespace", metricnamespace, 'str')

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
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Response', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/{resourceUri}/providers/microsoft.insights/metrics'}
