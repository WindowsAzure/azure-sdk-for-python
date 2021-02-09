# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, AsyncIterable, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.core.polling import AsyncLROPoller, AsyncNoPolling, AsyncPollingMethod
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.core.polling.async_arm_polling import AsyncARMPolling

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class AccountsOperations:
    """AccountsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.datalake.store.models
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

    def list(
        self,
        filter: Optional[str] = None,
        top: Optional[int] = None,
        skip: Optional[int] = None,
        select: Optional[str] = None,
        orderby: Optional[str] = None,
        count: Optional[bool] = None,
        **kwargs
    ) -> AsyncIterable["_models.DataLakeStoreAccountListResult"]:
        """Lists the Data Lake Store accounts within the subscription. The response includes a link to the
        next page of results, if any.

        :param filter: OData filter. Optional.
        :type filter: str
        :param top: The number of items to return. Optional.
        :type top: int
        :param skip: The number of items to skip over before returning elements. Optional.
        :type skip: int
        :param select: OData Select statement. Limits the properties on each entry to just those
         requested, e.g. Categories?$select=CategoryName,Description. Optional.
        :type select: str
        :param orderby: OrderBy clause. One or more comma-separated expressions with an optional "asc"
         (the default) or "desc" depending on the order you'd like the values sorted, e.g.
         Categories?$orderby=CategoryName desc. Optional.
        :type orderby: str
        :param count: The Boolean value of true or false to request a count of the matching resources
         included with the resources in the response, e.g. Categories?$count=true. Optional.
        :type count: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DataLakeStoreAccountListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.datalake.store.models.DataLakeStoreAccountListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataLakeStoreAccountListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-11-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
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
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('DataLakeStoreAccountListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.DataLakeStore/accounts'}  # type: ignore

    def list_by_resource_group(
        self,
        resource_group_name: str,
        filter: Optional[str] = None,
        top: Optional[int] = None,
        skip: Optional[int] = None,
        select: Optional[str] = None,
        orderby: Optional[str] = None,
        count: Optional[bool] = None,
        **kwargs
    ) -> AsyncIterable["_models.DataLakeStoreAccountListResult"]:
        """Lists the Data Lake Store accounts within a specific resource group. The response includes a
        link to the next page of results, if any.

        :param resource_group_name: The name of the Azure resource group.
        :type resource_group_name: str
        :param filter: OData filter. Optional.
        :type filter: str
        :param top: The number of items to return. Optional.
        :type top: int
        :param skip: The number of items to skip over before returning elements. Optional.
        :type skip: int
        :param select: OData Select statement. Limits the properties on each entry to just those
         requested, e.g. Categories?$select=CategoryName,Description. Optional.
        :type select: str
        :param orderby: OrderBy clause. One or more comma-separated expressions with an optional "asc"
         (the default) or "desc" depending on the order you'd like the values sorted, e.g.
         Categories?$orderby=CategoryName desc. Optional.
        :type orderby: str
        :param count: A Boolean value of true or false to request a count of the matching resources
         included with the resources in the response, e.g. Categories?$count=true. Optional.
        :type count: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DataLakeStoreAccountListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.datalake.store.models.DataLakeStoreAccountListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataLakeStoreAccountListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-11-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_resource_group.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
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
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('DataLakeStoreAccountListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts'}  # type: ignore

    async def _create_initial(
        self,
        resource_group_name: str,
        account_name: str,
        parameters: "_models.CreateDataLakeStoreAccountParameters",
        **kwargs
    ) -> "_models.DataLakeStoreAccount":
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataLakeStoreAccount"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-11-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self._create_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(parameters, 'CreateDataLakeStoreAccountParameters')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('DataLakeStoreAccount', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('DataLakeStoreAccount', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _create_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}'}  # type: ignore

    async def begin_create(
        self,
        resource_group_name: str,
        account_name: str,
        parameters: "_models.CreateDataLakeStoreAccountParameters",
        **kwargs
    ) -> AsyncLROPoller["_models.DataLakeStoreAccount"]:
        """Creates the specified Data Lake Store account.

        :param resource_group_name: The name of the Azure resource group.
        :type resource_group_name: str
        :param account_name: The name of the Data Lake Store account.
        :type account_name: str
        :param parameters: Parameters supplied to create the Data Lake Store account.
        :type parameters: ~azure.mgmt.datalake.store.models.CreateDataLakeStoreAccountParameters
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either DataLakeStoreAccount or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.mgmt.datalake.store.models.DataLakeStoreAccount]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataLakeStoreAccount"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._create_initial(
                resource_group_name=resource_group_name,
                account_name=account_name,
                parameters=parameters,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('DataLakeStoreAccount', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
        }

        if polling is True: polling_method = AsyncARMPolling(lro_delay, path_format_arguments=path_format_arguments,  **kwargs)
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        if cont_token:
            return AsyncLROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return AsyncLROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}'}  # type: ignore

    async def get(
        self,
        resource_group_name: str,
        account_name: str,
        **kwargs
    ) -> "_models.DataLakeStoreAccount":
        """Gets the specified Data Lake Store account.

        :param resource_group_name: The name of the Azure resource group.
        :type resource_group_name: str
        :param account_name: The name of the Data Lake Store account.
        :type account_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DataLakeStoreAccount, or the result of cls(response)
        :rtype: ~azure.mgmt.datalake.store.models.DataLakeStoreAccount
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataLakeStoreAccount"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-11-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
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
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DataLakeStoreAccount', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}'}  # type: ignore

    async def _update_initial(
        self,
        resource_group_name: str,
        account_name: str,
        parameters: "_models.UpdateDataLakeStoreAccountParameters",
        **kwargs
    ) -> "_models.DataLakeStoreAccount":
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataLakeStoreAccount"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-11-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self._update_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(parameters, 'UpdateDataLakeStoreAccountParameters')
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201, 202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('DataLakeStoreAccount', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('DataLakeStoreAccount', pipeline_response)

        if response.status_code == 202:
            deserialized = self._deserialize('DataLakeStoreAccount', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _update_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}'}  # type: ignore

    async def begin_update(
        self,
        resource_group_name: str,
        account_name: str,
        parameters: "_models.UpdateDataLakeStoreAccountParameters",
        **kwargs
    ) -> AsyncLROPoller["_models.DataLakeStoreAccount"]:
        """Updates the specified Data Lake Store account information.

        :param resource_group_name: The name of the Azure resource group.
        :type resource_group_name: str
        :param account_name: The name of the Data Lake Store account.
        :type account_name: str
        :param parameters: Parameters supplied to update the Data Lake Store account.
        :type parameters: ~azure.mgmt.datalake.store.models.UpdateDataLakeStoreAccountParameters
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either DataLakeStoreAccount or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.mgmt.datalake.store.models.DataLakeStoreAccount]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataLakeStoreAccount"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._update_initial(
                resource_group_name=resource_group_name,
                account_name=account_name,
                parameters=parameters,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('DataLakeStoreAccount', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
        }

        if polling is True: polling_method = AsyncARMPolling(lro_delay, path_format_arguments=path_format_arguments,  **kwargs)
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        if cont_token:
            return AsyncLROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return AsyncLROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}'}  # type: ignore

    async def _delete_initial(
        self,
        resource_group_name: str,
        account_name: str,
        **kwargs
    ) -> None:
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-11-01"

        # Construct URL
        url = self._delete_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    _delete_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}'}  # type: ignore

    async def begin_delete(
        self,
        resource_group_name: str,
        account_name: str,
        **kwargs
    ) -> AsyncLROPoller[None]:
        """Deletes the specified Data Lake Store account.

        :param resource_group_name: The name of the Azure resource group.
        :type resource_group_name: str
        :param account_name: The name of the Data Lake Store account.
        :type account_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either None or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[None]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._delete_initial(
                resource_group_name=resource_group_name,
                account_name=account_name,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
        }

        if polling is True: polling_method = AsyncARMPolling(lro_delay, path_format_arguments=path_format_arguments,  **kwargs)
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        if cont_token:
            return AsyncLROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return AsyncLROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}'}  # type: ignore

    async def enable_key_vault(
        self,
        resource_group_name: str,
        account_name: str,
        **kwargs
    ) -> None:
        """Attempts to enable a user managed Key Vault for encryption of the specified Data Lake Store
        account.

        :param resource_group_name: The name of the Azure resource group.
        :type resource_group_name: str
        :param account_name: The name of the Data Lake Store account.
        :type account_name: str
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
        api_version = "2016-11-01"

        # Construct URL
        url = self.enable_key_vault.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    enable_key_vault.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}/enableKeyVault'}  # type: ignore

    async def check_name_availability(
        self,
        location: str,
        parameters: "_models.CheckNameAvailabilityParameters",
        **kwargs
    ) -> "_models.NameAvailabilityInformation":
        """Checks whether the specified account name is available or taken.

        :param location: The resource location without whitespace.
        :type location: str
        :param parameters: Parameters supplied to check the Data Lake Store account name availability.
        :type parameters: ~azure.mgmt.datalake.store.models.CheckNameAvailabilityParameters
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: NameAvailabilityInformation, or the result of cls(response)
        :rtype: ~azure.mgmt.datalake.store.models.NameAvailabilityInformation
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.NameAvailabilityInformation"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-11-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.check_name_availability.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'location': self._serialize.url("location", location, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(parameters, 'CheckNameAvailabilityParameters')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('NameAvailabilityInformation', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    check_name_availability.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.DataLakeStore/locations/{location}/checkNameAvailability'}  # type: ignore
