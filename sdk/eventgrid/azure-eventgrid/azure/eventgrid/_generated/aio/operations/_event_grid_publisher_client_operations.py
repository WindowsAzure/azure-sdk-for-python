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

class EventGridPublisherClientOperationsMixin:

    async def publish_events(
        self,
        topic_hostname: str,
        events: List["_models.EventGridEvent"],
        **kwargs
    ) -> None:
        """Publishes a batch of events to an Azure Event Grid topic.

        :param topic_hostname: The host name of the topic, e.g. topic1.westus2-1.eventgrid.azure.net.
        :type topic_hostname: str
        :param events: An array of events to be published to Event Grid.
        :type events: list[~event_grid_publisher_client.models.EventGridEvent]
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
        api_version = "2018-01-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self.publish_events.metadata['url']  # type: ignore
        path_format_arguments = {
            'topicHostname': self._serialize.url("topic_hostname", topic_hostname, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(events, '[EventGridEvent]')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if cls:
            return cls(pipeline_response, None, {})

    publish_events.metadata = {'url': '/api/events'}  # type: ignore

    async def publish_cloud_event_events(
        self,
        topic_hostname: str,
        events: List["_models.CloudEvent"],
        **kwargs
    ) -> None:
        """Publishes a batch of events to an Azure Event Grid topic.

        :param topic_hostname: The host name of the topic, e.g. topic1.westus2-1.eventgrid.azure.net.
        :type topic_hostname: str
        :param events: An array of events to be published to Event Grid.
        :type events: list[~event_grid_publisher_client.models.CloudEvent]
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
        api_version = "2018-01-01"
        content_type = kwargs.pop("content_type", "application/cloudevents-batch+json; charset=utf-8")

        # Construct URL
        url = self.publish_cloud_event_events.metadata['url']  # type: ignore
        path_format_arguments = {
            'topicHostname': self._serialize.url("topic_hostname", topic_hostname, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(events, '[CloudEvent]')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if cls:
            return cls(pipeline_response, None, {})

    publish_cloud_event_events.metadata = {'url': '/api/events'}  # type: ignore

    async def publish_custom_event_events(
        self,
        topic_hostname: str,
        events: List[object],
        **kwargs
    ) -> None:
        """Publishes a batch of events to an Azure Event Grid topic.

        :param topic_hostname: The host name of the topic, e.g. topic1.westus2-1.eventgrid.azure.net.
        :type topic_hostname: str
        :param events: An array of events to be published to Event Grid.
        :type events: list[object]
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
        api_version = "2018-01-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self.publish_custom_event_events.metadata['url']  # type: ignore
        path_format_arguments = {
            'topicHostname': self._serialize.url("topic_hostname", topic_hostname, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(events, '[object]')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if cls:
            return cls(pipeline_response, None, {})

    publish_custom_event_events.metadata = {'url': ''}  # type: ignore
