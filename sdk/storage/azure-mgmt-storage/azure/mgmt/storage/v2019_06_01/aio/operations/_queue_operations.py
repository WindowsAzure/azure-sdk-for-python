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

class QueueOperations:
    """QueueOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.storage.v2019_06_01.models
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

    async def create(
        self,
        resource_group_name: str,
        account_name: str,
        queue_name: str,
        queue: "_models.StorageQueue",
        **kwargs
    ) -> "_models.StorageQueue":
        """Creates a new queue with the specified queue name, under the specified account.

        :param resource_group_name: The name of the resource group within the user's subscription. The
         name is case insensitive.
        :type resource_group_name: str
        :param account_name: The name of the storage account within the specified resource group.
         Storage account names must be between 3 and 24 characters in length and use numbers and lower-
         case letters only.
        :type account_name: str
        :param queue_name: A queue name must be unique within a storage account and must be between 3
         and 63 characters.The name must comprise of lowercase alphanumeric and dash(-) characters only,
         it should begin and end with an alphanumeric character and it cannot have two consecutive
         dash(-) characters.
        :type queue_name: str
        :param queue: Queue properties and metadata to be created with.
        :type queue: ~azure.mgmt.storage.v2019_06_01.models.StorageQueue
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: StorageQueue, or the result of cls(response)
        :rtype: ~azure.mgmt.storage.v2019_06_01.models.StorageQueue
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.StorageQueue"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
            'queueName': self._serialize.url("queue_name", queue_name, 'str', max_length=63, min_length=3, pattern=r'^[a-z0-9]([a-z0-9]|(-(?!-))){1,61}[a-z0-9]$'),
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
        body_content = self._serialize.body(queue, 'StorageQueue')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('StorageQueue', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/queueServices/default/queues/{queueName}'}  # type: ignore

    async def update(
        self,
        resource_group_name: str,
        account_name: str,
        queue_name: str,
        queue: "_models.StorageQueue",
        **kwargs
    ) -> "_models.StorageQueue":
        """Creates a new queue with the specified queue name, under the specified account.

        :param resource_group_name: The name of the resource group within the user's subscription. The
         name is case insensitive.
        :type resource_group_name: str
        :param account_name: The name of the storage account within the specified resource group.
         Storage account names must be between 3 and 24 characters in length and use numbers and lower-
         case letters only.
        :type account_name: str
        :param queue_name: A queue name must be unique within a storage account and must be between 3
         and 63 characters.The name must comprise of lowercase alphanumeric and dash(-) characters only,
         it should begin and end with an alphanumeric character and it cannot have two consecutive
         dash(-) characters.
        :type queue_name: str
        :param queue: Queue properties and metadata to be created with.
        :type queue: ~azure.mgmt.storage.v2019_06_01.models.StorageQueue
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: StorageQueue, or the result of cls(response)
        :rtype: ~azure.mgmt.storage.v2019_06_01.models.StorageQueue
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.StorageQueue"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.update.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
            'queueName': self._serialize.url("queue_name", queue_name, 'str', max_length=63, min_length=3, pattern=r'^[a-z0-9]([a-z0-9]|(-(?!-))){1,61}[a-z0-9]$'),
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
        body_content = self._serialize.body(queue, 'StorageQueue')
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('StorageQueue', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/queueServices/default/queues/{queueName}'}  # type: ignore

    async def get(
        self,
        resource_group_name: str,
        account_name: str,
        queue_name: str,
        **kwargs
    ) -> "_models.StorageQueue":
        """Gets the queue with the specified queue name, under the specified account if it exists.

        :param resource_group_name: The name of the resource group within the user's subscription. The
         name is case insensitive.
        :type resource_group_name: str
        :param account_name: The name of the storage account within the specified resource group.
         Storage account names must be between 3 and 24 characters in length and use numbers and lower-
         case letters only.
        :type account_name: str
        :param queue_name: A queue name must be unique within a storage account and must be between 3
         and 63 characters.The name must comprise of lowercase alphanumeric and dash(-) characters only,
         it should begin and end with an alphanumeric character and it cannot have two consecutive
         dash(-) characters.
        :type queue_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: StorageQueue, or the result of cls(response)
        :rtype: ~azure.mgmt.storage.v2019_06_01.models.StorageQueue
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.StorageQueue"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
            'queueName': self._serialize.url("queue_name", queue_name, 'str', max_length=63, min_length=3, pattern=r'^[a-z0-9]([a-z0-9]|(-(?!-))){1,61}[a-z0-9]$'),
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

        deserialized = self._deserialize('StorageQueue', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/queueServices/default/queues/{queueName}'}  # type: ignore

    async def delete(
        self,
        resource_group_name: str,
        account_name: str,
        queue_name: str,
        **kwargs
    ) -> None:
        """Deletes the queue with the specified queue name, under the specified account if it exists.

        :param resource_group_name: The name of the resource group within the user's subscription. The
         name is case insensitive.
        :type resource_group_name: str
        :param account_name: The name of the storage account within the specified resource group.
         Storage account names must be between 3 and 24 characters in length and use numbers and lower-
         case letters only.
        :type account_name: str
        :param queue_name: A queue name must be unique within a storage account and must be between 3
         and 63 characters.The name must comprise of lowercase alphanumeric and dash(-) characters only,
         it should begin and end with an alphanumeric character and it cannot have two consecutive
         dash(-) characters.
        :type queue_name: str
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
        api_version = "2019-06-01"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
            'queueName': self._serialize.url("queue_name", queue_name, 'str', max_length=63, min_length=3, pattern=r'^[a-z0-9]([a-z0-9]|(-(?!-))){1,61}[a-z0-9]$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/queueServices/default/queues/{queueName}'}  # type: ignore

    def list(
        self,
        resource_group_name: str,
        account_name: str,
        maxpagesize: Optional[str] = None,
        filter: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["_models.ListQueueResource"]:
        """Gets a list of all the queues under the specified storage account.

        :param resource_group_name: The name of the resource group within the user's subscription. The
         name is case insensitive.
        :type resource_group_name: str
        :param account_name: The name of the storage account within the specified resource group.
         Storage account names must be between 3 and 24 characters in length and use numbers and lower-
         case letters only.
        :type account_name: str
        :param maxpagesize: Optional, a maximum number of queues that should be included in a list
         queue response.
        :type maxpagesize: str
        :param filter: Optional, When specified, only the queues with a name starting with the given
         filter will be listed.
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either ListQueueResource or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.storage.v2019_06_01.models.ListQueueResource]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ListQueueResource"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if maxpagesize is not None:
                    query_parameters['$maxpagesize'] = self._serialize.query("maxpagesize", maxpagesize, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('ListQueueResource', pipeline_response)
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
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/queueServices/default/queues'}  # type: ignore
