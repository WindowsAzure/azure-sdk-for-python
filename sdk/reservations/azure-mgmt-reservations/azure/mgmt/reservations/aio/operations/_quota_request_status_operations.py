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

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class QuotaRequestStatusOperations:
    """QuotaRequestStatusOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.reservations.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    async def get(
        self,
        subscription_id: str,
        provider_id: str,
        location: str,
        id: str,
        **kwargs
    ) -> "_models.QuotaRequestDetails":
        """For the specified Azure region (location), get the details and status of the quota request by
        the quota request ID for the resources of the resource provider. The PUT request for the quota
        (service limit) returns a response with the requestId parameter.

        :param subscription_id: Azure subscription ID.
        :type subscription_id: str
        :param provider_id: Azure resource provider ID.
        :type provider_id: str
        :param location: Azure region.
        :type location: str
        :param id: Quota Request ID.
        :type id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: QuotaRequestDetails, or the result of cls(response)
        :rtype: ~azure.mgmt.reservations.models.QuotaRequestDetails
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.QuotaRequestDetails"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-10-25"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
            'providerId': self._serialize.url("provider_id", provider_id, 'str'),
            'location': self._serialize.url("location", location, 'str'),
            'id': self._serialize.url("id", id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.ExceptionResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('QuotaRequestDetails', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Capacity/resourceProviders/{providerId}/locations/{location}/serviceLimitsRequests/{id}'}  # type: ignore

    def list(
        self,
        subscription_id: str,
        provider_id: str,
        location: str,
        filter: Optional[str] = None,
        top: Optional[int] = None,
        skiptoken: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["_models.QuotaRequestDetailsList"]:
        """For the specified Azure region (location), subscription, and resource provider, get the history
        of the quota requests for the past year. To select specific quota requests, use the oData
        filter.

        :param subscription_id: Azure subscription ID.
        :type subscription_id: str
        :param provider_id: Azure resource provider ID.
        :type provider_id: str
        :param location: Azure region.
        :type location: str
        :param filter: .. list-table::
            :header-rows: 1

            * - Field
              - Supported operators
            * -


         |requestSubmitTime | ge, le, eq, gt, lt.
        :type filter: str
        :param top: Number of records to return.
        :type top: int
        :param skiptoken: Skiptoken is only used if a previous operation returned a partial result. If
         a previous response contains a nextLink element, the value of the nextLink element includes a
         skiptoken parameter that specifies a starting point to use for subsequent calls.
        :type skiptoken: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either QuotaRequestDetailsList or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.reservations.models.QuotaRequestDetailsList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.QuotaRequestDetailsList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-10-25"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
                    'providerId': self._serialize.url("provider_id", provider_id, 'str'),
                    'location': self._serialize.url("location", location, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', minimum=1)
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('QuotaRequestDetailsList', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(_models.ExceptionResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Capacity/resourceProviders/{providerId}/locations/{location}/serviceLimitsRequests'}  # type: ignore
