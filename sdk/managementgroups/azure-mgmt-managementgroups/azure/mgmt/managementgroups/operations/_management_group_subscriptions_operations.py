# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class ManagementGroupSubscriptionsOperations(object):
    """ManagementGroupSubscriptionsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.managementgroups.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def create(
        self,
        group_id,  # type: str
        subscription_id,  # type: str
        cache_control="no-cache",  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.SubscriptionUnderManagementGroup"
        """Associates existing subscription with the management group.

        :param group_id: Management Group ID.
        :type group_id: str
        :param subscription_id: Subscription ID.
        :type subscription_id: str
        :param cache_control: Indicates whether the request should utilize any caches. Populate the
         header with 'no-cache' value to bypass existing caches.
        :type cache_control: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SubscriptionUnderManagementGroup, or the result of cls(response)
        :rtype: ~azure.mgmt.managementgroups.models.SubscriptionUnderManagementGroup
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SubscriptionUnderManagementGroup"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-04-01"
        accept = "application/json"

        # Construct URL
        url = self.create.metadata['url']  # type: ignore
        path_format_arguments = {
            'groupId': self._serialize.url("group_id", group_id, 'str'),
            'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if cache_control is not None:
            header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.put(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('SubscriptionUnderManagementGroup', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}/subscriptions/{subscriptionId}'}  # type: ignore

    def delete(
        self,
        group_id,  # type: str
        subscription_id,  # type: str
        cache_control="no-cache",  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """De-associates subscription from the management group.

        :param group_id: Management Group ID.
        :type group_id: str
        :param subscription_id: Subscription ID.
        :type subscription_id: str
        :param cache_control: Indicates whether the request should utilize any caches. Populate the
         header with 'no-cache' value to bypass existing caches.
        :type cache_control: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-04-01"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'groupId': self._serialize.url("group_id", group_id, 'str'),
            'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if cache_control is not None:
            header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}/subscriptions/{subscriptionId}'}  # type: ignore

    def get_subscription(
        self,
        group_id,  # type: str
        subscription_id,  # type: str
        cache_control="no-cache",  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.SubscriptionUnderManagementGroup"
        """Retrieves details about given subscription which is associated with the management group.

        :param group_id: Management Group ID.
        :type group_id: str
        :param subscription_id: Subscription ID.
        :type subscription_id: str
        :param cache_control: Indicates whether the request should utilize any caches. Populate the
         header with 'no-cache' value to bypass existing caches.
        :type cache_control: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SubscriptionUnderManagementGroup, or the result of cls(response)
        :rtype: ~azure.mgmt.managementgroups.models.SubscriptionUnderManagementGroup
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SubscriptionUnderManagementGroup"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-04-01"
        accept = "application/json"

        # Construct URL
        url = self.get_subscription.metadata['url']  # type: ignore
        path_format_arguments = {
            'groupId': self._serialize.url("group_id", group_id, 'str'),
            'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if cache_control is not None:
            header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('SubscriptionUnderManagementGroup', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_subscription.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}/subscriptions/{subscriptionId}'}  # type: ignore

    def get_subscriptions_under_management_group(
        self,
        group_id,  # type: str
        skiptoken=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["_models.ListSubscriptionUnderManagementGroup"]
        """Retrieves details about all subscriptions which are associated with the management group.

        :param group_id: Management Group ID.
        :type group_id: str
        :param skiptoken: Page continuation token is only used if a previous operation returned a
         partial result.
         If a previous response contains a nextLink element, the value of the nextLink element will
         include a token parameter that specifies a starting point to use for subsequent calls.
        :type skiptoken: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either ListSubscriptionUnderManagementGroup or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.managementgroups.models.ListSubscriptionUnderManagementGroup]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ListSubscriptionUnderManagementGroup"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-04-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.get_subscriptions_under_management_group.metadata['url']  # type: ignore
                path_format_arguments = {
                    'groupId': self._serialize.url("group_id", group_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('ListSubscriptionUnderManagementGroup', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    get_subscriptions_under_management_group.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}/subscriptions'}  # type: ignore
