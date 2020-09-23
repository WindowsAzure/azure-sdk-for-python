# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, AsyncIterable, Callable, Dict, Generic, Optional, TypeVar
import warnings

from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class TenantActivityLogsOperations:
    """TenantActivityLogsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~$(python-base-namespace).v2015_04_01.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def list(
        self,
        filter: Optional[str] = None,
        select: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["models.EventDataCollection"]:
        """Gets the Activity Logs for the Tenant.:code:`<br>`Everything that is applicable to the API to
        get the Activity Logs for the subscription is applicable to this API (the parameters, $filter,
        etc.).:code:`<br>`One thing to point out here is that this API does *not* retrieve the logs at
        the individual subscription of the tenant but only surfaces the logs that were generated at the
        tenant level.

        :param filter: Reduces the set of data collected. :code:`<br>`The **$filter** is very
         restricted and allows only the following patterns.:code:`<br>`- List events for a resource
         group: $filter=eventTimestamp ge ':code:`<Start Time>`' and eventTimestamp le ':code:`<End
         Time>`' and eventChannels eq 'Admin, Operation' and resourceGroupName eq
         ':code:`<ResourceGroupName>`'.:code:`<br>`- List events for resource: $filter=eventTimestamp ge
         ':code:`<Start Time>`' and eventTimestamp le ':code:`<End Time>`' and eventChannels eq 'Admin,
         Operation' and resourceUri eq ':code:`<ResourceURI>`'.:code:`<br>`- List events for a
         subscription: $filter=eventTimestamp ge ':code:`<Start Time>`' and eventTimestamp le
         ':code:`<End Time>`' and eventChannels eq 'Admin, Operation'.:code:`<br>`- List events for a
         resource provider: $filter=eventTimestamp ge ':code:`<Start Time>`' and eventTimestamp le
         ':code:`<End Time>`' and eventChannels eq 'Admin, Operation' and resourceProvider eq
         ':code:`<ResourceProviderName>`'.:code:`<br>`- List events for a correlation Id: api-
         version=2014-04-01&$filter=eventTimestamp ge '2014-07-16T04:36:37.6407898Z' and eventTimestamp
         le '2014-07-20T04:36:37.6407898Z' and eventChannels eq 'Admin, Operation' and correlationId eq
         ':code:`<CorrelationID>`'.:code:`<br>`\ **NOTE**\ : No other syntax is allowed.
        :type filter: str
        :param select: Used to fetch events with only the given properties.:code:`<br>`The **$select**
         argument is a comma separated list of property names to be returned. Possible values are:
         *authorization*\ , *claims*\ , *correlationId*\ , *description*\ , *eventDataId*\ ,
         *eventName*\ , *eventTimestamp*\ , *httpRequest*\ , *level*\ , *operationId*\ ,
         *operationName*\ , *properties*\ , *resourceGroupName*\ , *resourceProviderName*\ ,
         *resourceId*\ , *status*\ , *submissionTimestamp*\ , *subStatus*\ , *subscriptionId*.
        :type select: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either EventDataCollection or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~$(python-base-namespace).v2015_04_01.models.EventDataCollection]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.EventDataCollection"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2015-04-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if select is not None:
                    query_parameters['$select'] = self._serialize.query("select", select, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('EventDataCollection', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/providers/microsoft.insights/eventtypes/management/values'}  # type: ignore
