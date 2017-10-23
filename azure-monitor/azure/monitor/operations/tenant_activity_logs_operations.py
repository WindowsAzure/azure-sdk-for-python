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


class TenantActivityLogsOperations(object):
    """TenantActivityLogsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2015-04-01".
    """

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2015-04-01"

        self.config = config

    def list(
            self, filter=None, select=None, custom_headers=None, raw=False, **operation_config):
        """Gets the Activity Logs for the Tenant.<br>Everything that is applicable
        to the API to get the Activity Logs for the subscription is applicable
        to this API (the parameters, $filter, etc.).<br>One thing to point out
        here is that this API does *not* retrieve the logs at the individual
        subscription of the tenant but only surfaces the logs that were
        generated at the tenant level.

        :param filter: Reduces the set of data collected. <br>The **$filter**
         is very restricted and allows only the following patterns.<br>- List
         events for a resource group: $filter=eventTimestamp ge '<Start Time>'
         and eventTimestamp le '<End Time>' and eventChannels eq 'Admin,
         Operation' and resourceGroupName eq '<ResourceGroupName>'.<br>- List
         events for resource: $filter=eventTimestamp ge '<Start Time>' and
         eventTimestamp le '<End Time>' and eventChannels eq 'Admin, Operation'
         and resourceUri eq '<ResourceURI>'.<br>- List events for a
         subscription: $filter=eventTimestamp ge '<Start Time>' and
         eventTimestamp le '<End Time>' and eventChannels eq 'Admin,
         Operation'.<br>- List evetns for a resource provider:
         $filter=eventTimestamp ge '<Start Time>' and eventTimestamp le '<End
         Time>' and eventChannels eq 'Admin, Operation' and resourceProvider eq
         '<ResourceProviderName>'.<br>- List events for a correlation Id:
         api-version=2014-04-01&$filter=eventTimestamp ge
         '2014-07-16T04:36:37.6407898Z' and eventTimestamp le
         '2014-07-20T04:36:37.6407898Z' and eventChannels eq 'Admin, Operation'
         and correlationId eq '<CorrelationID>'.<br>**NOTE**: No other syntax
         is allowed.
        :type filter: str
        :param select: Used to fetch events with only the given
         properties.<br>The **$select** argument is a comma separated list of
         property names to be returned. Possible values are: *authorization*,
         *claims*, *correlationId*, *description*, *eventDataId*, *eventName*,
         *eventTimestamp*, *httpRequest*, *level*, *operationId*,
         *operationName*, *properties*, *resourceGroupName*,
         *resourceProviderName*, *resourceId*, *status*, *submissionTimestamp*,
         *subStatus*, *subscriptionId*
        :type select: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of :class:`EventData
         <azure.monitor.models.EventData>`
        :rtype: :class:`EventDataPaged <azure.monitor.models.EventDataPaged>`
        :raises:
         :class:`ErrorResponseException<azure.monitor.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/providers/microsoft.insights/eventtypes/management/values'

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if select is not None:
                    query_parameters['$select'] = self._serialize.query("select", select, 'str')

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
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.EventDataPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.EventDataPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
