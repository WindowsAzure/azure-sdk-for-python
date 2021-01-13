# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class MessagesOperations:
    """MessagesOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.storage.queue.models
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

    async def dequeue(
        self,
        number_of_messages: Optional[int] = None,
        visibilitytimeout: Optional[int] = None,
        timeout: Optional[int] = None,
        request_id_parameter: Optional[str] = None,
        **kwargs
    ) -> List["_models.DequeuedMessageItem"]:
        """The Dequeue operation retrieves one or more messages from the front of the queue.

        :param number_of_messages: Optional. A nonzero integer value that specifies the number of
         messages to retrieve from the queue, up to a maximum of 32. If fewer are visible, the visible
         messages are returned. By default, a single message is retrieved from the queue with this
         operation.
        :type number_of_messages: int
        :param visibilitytimeout: Optional. Specifies the new visibility timeout value, in seconds,
         relative to server time. The default value is 30 seconds. A specified value must be larger than
         or equal to 1 second, and cannot be larger than 7 days, or larger than 2 hours on REST protocol
         versions prior to version 2011-08-18. The visibility timeout of a message can be set to a value
         later than the expiry time.
        :type visibilitytimeout: int
        :param timeout: The The timeout parameter is expressed in seconds. For more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/setting-timeouts-for-queue-
         service-operations>Setting Timeouts for Queue Service Operations.</a>.
        :type timeout: int
        :param request_id_parameter: Provides a client-generated, opaque value with a 1 KB character
         limit that is recorded in the analytics logs when storage analytics logging is enabled.
        :type request_id_parameter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: list of DequeuedMessageItem, or the result of cls(response)
        :rtype: list[~azure.storage.queue.models.DequeuedMessageItem]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[List["_models.DequeuedMessageItem"]]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/xml"

        # Construct URL
        url = self.dequeue.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if number_of_messages is not None:
            query_parameters['numofmessages'] = self._serialize.query("number_of_messages", number_of_messages, 'int', minimum=1)
        if visibilitytimeout is not None:
            query_parameters['visibilitytimeout'] = self._serialize.query("visibilitytimeout", visibilitytimeout, 'int', maximum=604800, minimum=0)
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id_parameter is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id_parameter", request_id_parameter, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.StorageError, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['x-ms-request-id']=self._deserialize('str', response.headers.get('x-ms-request-id'))
        response_headers['x-ms-version']=self._deserialize('str', response.headers.get('x-ms-version'))
        response_headers['Date']=self._deserialize('rfc-1123', response.headers.get('Date'))
        deserialized = self._deserialize('[DequeuedMessageItem]', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    dequeue.metadata = {'url': '/{queueName}/messages'}  # type: ignore

    async def clear(
        self,
        timeout: Optional[int] = None,
        request_id_parameter: Optional[str] = None,
        **kwargs
    ) -> None:
        """The Clear operation deletes all messages from the specified queue.

        :param timeout: The The timeout parameter is expressed in seconds. For more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/setting-timeouts-for-queue-
         service-operations>Setting Timeouts for Queue Service Operations.</a>.
        :type timeout: int
        :param request_id_parameter: Provides a client-generated, opaque value with a 1 KB character
         limit that is recorded in the analytics logs when storage analytics logging is enabled.
        :type request_id_parameter: str
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
        accept = "application/xml"

        # Construct URL
        url = self.clear.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id_parameter is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id_parameter", request_id_parameter, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.StorageError, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['x-ms-request-id']=self._deserialize('str', response.headers.get('x-ms-request-id'))
        response_headers['x-ms-version']=self._deserialize('str', response.headers.get('x-ms-version'))
        response_headers['Date']=self._deserialize('rfc-1123', response.headers.get('Date'))

        if cls:
            return cls(pipeline_response, None, response_headers)

    clear.metadata = {'url': '/{queueName}/messages'}  # type: ignore

    async def enqueue(
        self,
        queue_message: "_models.QueueMessage",
        visibilitytimeout: Optional[int] = None,
        message_time_to_live: Optional[int] = None,
        timeout: Optional[int] = None,
        request_id_parameter: Optional[str] = None,
        **kwargs
    ) -> List["_models.EnqueuedMessage"]:
        """The Enqueue operation adds a new message to the back of the message queue. A visibility timeout
        can also be specified to make the message invisible until the visibility timeout expires. A
        message must be in a format that can be included in an XML request with UTF-8 encoding. The
        encoded message can be up to 64 KB in size for versions 2011-08-18 and newer, or 8 KB in size
        for previous versions.

        :param queue_message: A Message object which can be stored in a Queue.
        :type queue_message: ~azure.storage.queue.models.QueueMessage
        :param visibilitytimeout: Optional. If specified, the request must be made using an x-ms-
         version of 2011-08-18 or later. If not specified, the default value is 0. Specifies the new
         visibility timeout value, in seconds, relative to server time. The new value must be larger
         than or equal to 0, and cannot be larger than 7 days. The visibility timeout of a message
         cannot be set to a value later than the expiry time. visibilitytimeout should be set to a value
         smaller than the time-to-live value.
        :type visibilitytimeout: int
        :param message_time_to_live: Optional. Specifies the time-to-live interval for the message, in
         seconds. Prior to version 2017-07-29, the maximum time-to-live allowed is 7 days. For version
         2017-07-29 or later, the maximum time-to-live can be any positive number, as well as -1
         indicating that the message does not expire. If this parameter is omitted, the default time-to-
         live is 7 days.
        :type message_time_to_live: int
        :param timeout: The The timeout parameter is expressed in seconds. For more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/setting-timeouts-for-queue-
         service-operations>Setting Timeouts for Queue Service Operations.</a>.
        :type timeout: int
        :param request_id_parameter: Provides a client-generated, opaque value with a 1 KB character
         limit that is recorded in the analytics logs when storage analytics logging is enabled.
        :type request_id_parameter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: list of EnqueuedMessage, or the result of cls(response)
        :rtype: list[~azure.storage.queue.models.EnqueuedMessage]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[List["_models.EnqueuedMessage"]]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        content_type = kwargs.pop("content_type", "application/xml")
        accept = "application/xml"

        # Construct URL
        url = self.enqueue.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if visibilitytimeout is not None:
            query_parameters['visibilitytimeout'] = self._serialize.query("visibilitytimeout", visibilitytimeout, 'int', maximum=604800, minimum=0)
        if message_time_to_live is not None:
            query_parameters['messagettl'] = self._serialize.query("message_time_to_live", message_time_to_live, 'int', minimum=-1)
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id_parameter is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id_parameter", request_id_parameter, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(queue_message, 'QueueMessage', is_xml=True)
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.StorageError, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['x-ms-request-id']=self._deserialize('str', response.headers.get('x-ms-request-id'))
        response_headers['x-ms-version']=self._deserialize('str', response.headers.get('x-ms-version'))
        response_headers['Date']=self._deserialize('rfc-1123', response.headers.get('Date'))
        deserialized = self._deserialize('[EnqueuedMessage]', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    enqueue.metadata = {'url': '/{queueName}/messages'}  # type: ignore

    async def peek(
        self,
        number_of_messages: Optional[int] = None,
        timeout: Optional[int] = None,
        request_id_parameter: Optional[str] = None,
        **kwargs
    ) -> List["_models.PeekedMessageItem"]:
        """The Peek operation retrieves one or more messages from the front of the queue, but does not
        alter the visibility of the message.

        :param number_of_messages: Optional. A nonzero integer value that specifies the number of
         messages to retrieve from the queue, up to a maximum of 32. If fewer are visible, the visible
         messages are returned. By default, a single message is retrieved from the queue with this
         operation.
        :type number_of_messages: int
        :param timeout: The The timeout parameter is expressed in seconds. For more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/setting-timeouts-for-queue-
         service-operations>Setting Timeouts for Queue Service Operations.</a>.
        :type timeout: int
        :param request_id_parameter: Provides a client-generated, opaque value with a 1 KB character
         limit that is recorded in the analytics logs when storage analytics logging is enabled.
        :type request_id_parameter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: list of PeekedMessageItem, or the result of cls(response)
        :rtype: list[~azure.storage.queue.models.PeekedMessageItem]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[List["_models.PeekedMessageItem"]]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        peekonly = "true"
        accept = "application/xml"

        # Construct URL
        url = self.peek.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['peekonly'] = self._serialize.query("peekonly", peekonly, 'str')
        if number_of_messages is not None:
            query_parameters['numofmessages'] = self._serialize.query("number_of_messages", number_of_messages, 'int', minimum=1)
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id_parameter is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id_parameter", request_id_parameter, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.StorageError, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['x-ms-request-id']=self._deserialize('str', response.headers.get('x-ms-request-id'))
        response_headers['x-ms-version']=self._deserialize('str', response.headers.get('x-ms-version'))
        response_headers['Date']=self._deserialize('rfc-1123', response.headers.get('Date'))
        deserialized = self._deserialize('[PeekedMessageItem]', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    peek.metadata = {'url': '/{queueName}/messages'}  # type: ignore
