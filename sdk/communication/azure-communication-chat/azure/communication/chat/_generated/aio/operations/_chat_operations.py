# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import Any, AsyncIterable, Callable, Dict, Generic, Optional, TypeVar
import warnings

from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class ChatOperations:
    """ChatOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.communication.chat.models
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

    async def create_chat_thread(
        self,
        create_chat_thread_request: "_models.CreateChatThreadRequest",
        repeatability_request_id: Optional[str] = None,
        **kwargs
    ) -> "_models.CreateChatThreadResult":
        """Creates a chat thread.

        Creates a chat thread.

        :param create_chat_thread_request: Request payload for creating a chat thread.
        :type create_chat_thread_request: ~azure.communication.chat.models.CreateChatThreadRequest
        :param repeatability_request_id: If specified, the client directs that the request is
         repeatable; that is, that the client can make the request multiple times with the same
         Repeatability-Request-Id and get back an appropriate response without the server executing the
         request multiple times. The value of the Repeatability-Request-Id is an opaque string
         representing a client-generated, globally unique for all time, identifier for the request. It
         is recommended to use version 4 (random) UUIDs.
        :type repeatability_request_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CreateChatThreadResult, or the result of cls(response)
        :rtype: ~azure.communication.chat.models.CreateChatThreadResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CreateChatThreadResult"]
        error_map = {
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            401: lambda response: ClientAuthenticationError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            403: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            429: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            503: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-03-07"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create_chat_thread.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if repeatability_request_id is not None:
            header_parameters['repeatability-Request-Id'] = self._serialize.header("repeatability_request_id", repeatability_request_id, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(create_chat_thread_request, 'CreateChatThreadRequest')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('CreateChatThreadResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_chat_thread.metadata = {'url': '/chat/threads'}  # type: ignore

    def list_chat_threads(
        self,
        max_page_size: Optional[int] = None,
        start_time: Optional[datetime.datetime] = None,
        **kwargs
    ) -> AsyncIterable["_models.ChatThreadsItemCollection"]:
        """Gets the list of chat threads of a user.

        Gets the list of chat threads of a user.

        :param max_page_size: The maximum number of chat threads returned per page.
        :type max_page_size: int
        :param start_time: The earliest point in time to get chat threads up to. The timestamp should
         be in RFC3339 format: ``yyyy-MM-ddTHH:mm:ssZ``.
        :type start_time: ~datetime.datetime
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either ChatThreadsItemCollection or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.communication.chat.models.ChatThreadsItemCollection]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ChatThreadsItemCollection"]
        error_map = {
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            401: lambda response: ClientAuthenticationError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            403: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            429: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            503: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-03-07"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_chat_threads.metadata['url']  # type: ignore
                path_format_arguments = {
                    'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if max_page_size is not None:
                    query_parameters['maxPageSize'] = self._serialize.query("max_page_size", max_page_size, 'int')
                if start_time is not None:
                    query_parameters['startTime'] = self._serialize.query("start_time", start_time, 'iso-8601')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                path_format_arguments = {
                    'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                }
                url = self._client.format_url(url, **path_format_arguments)
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('ChatThreadsItemCollection', pipeline_response)
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
                raise HttpResponseError(response=response)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_chat_threads.metadata = {'url': '/chat/threads'}  # type: ignore

    async def delete_chat_thread(
        self,
        chat_thread_id: str,
        **kwargs
    ) -> None:
        """Deletes a thread.

        Deletes a thread.

        :param chat_thread_id: Id of the thread to be deleted.
        :type chat_thread_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            401: lambda response: ClientAuthenticationError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            403: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            429: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
            503: lambda response: HttpResponseError(response=response, model=self._deserialize(_models.CommunicationErrorResponse, response)),
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-03-07"
        accept = "application/json"

        # Construct URL
        url = self.delete_chat_thread.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'chatThreadId': self._serialize.url("chat_thread_id", chat_thread_id, 'str'),
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
            raise HttpResponseError(response=response)

        if cls:
            return cls(pipeline_response, None, {})

    delete_chat_thread.metadata = {'url': '/chat/threads/{chatThreadId}'}  # type: ignore
