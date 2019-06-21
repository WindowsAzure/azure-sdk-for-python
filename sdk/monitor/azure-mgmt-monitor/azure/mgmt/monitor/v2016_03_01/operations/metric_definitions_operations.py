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


class MetricDefinitionsOperations(object):
    """MetricDefinitionsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2016-03-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2016-03-01"

        self.config = config

    def list(
            self, resource_uri, filter=None, custom_headers=None, raw=False, **operation_config):
        """Lists the metric definitions for the resource.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :param filter: Reduces the set of data collected by retrieving
         particular metric definitions from all the definitions available for
         the resource.<br>For example, to get just the definition for the 'CPU
         percentage' counter: $filter=name.value eq '\\Processor(_Total)\\%
         Processor Time'.<br>Multiple metrics can be retrieved by joining
         together *'name eq <value>'* clauses separated by *or* logical
         operators.<br>**NOTE**: No other syntax is allowed.
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of MetricDefinition
        :rtype:
         ~azure.mgmt.monitor.v2016_03_01.models.MetricDefinitionPaged[~azure.mgmt.monitor.v2016_03_01.models.MetricDefinition]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.monitor.v2016_03_01.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True)
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

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
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.MetricDefinitionPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.MetricDefinitionPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/{resourceUri}/providers/microsoft.insights/metricDefinitions'}
