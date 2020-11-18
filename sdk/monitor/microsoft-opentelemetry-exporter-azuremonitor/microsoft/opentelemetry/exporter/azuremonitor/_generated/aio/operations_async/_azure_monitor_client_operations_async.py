# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest

from ... import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class AzureMonitorClientOperationsMixin:

    async def track(
        self,
        body: List["models.TelemetryItem"],
        **kwargs
    ) -> "models.TrackResponse":
        """Track telemetry events.

        This operation sends a sequence of telemetry events that will be monitored by Azure Monitor.

        :param body: The list of telemetry events to track.
        :type body: list[~azure_monitor_client.models.TelemetryItem]
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: TrackResponse, or the result of cls(response)
        :rtype: ~azure_monitor_client.models.TrackResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.TrackResponse"]
        error_map = {
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            400: lambda response: HttpResponseError(response=response, model=self._deserialize(models.TrackResponse, response)),
            402: lambda response: HttpResponseError(response=response, model=self._deserialize(models.TrackResponse, response)),
            429: lambda response: HttpResponseError(response=response, model=self._deserialize(models.TrackResponse, response)),
            500: lambda response: HttpResponseError(response=response, model=self._deserialize(models.TrackResponse, response)),
            503: lambda response: HttpResponseError(response=response, model=self._deserialize(models.TrackResponse, response)),
        }
        error_map.update(kwargs.pop('error_map', {}))
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self.track.metadata['url']  # type: ignore
        path_format_arguments = {
            'Host': self._serialize.url("self._config.host", self._config.host, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(body, '[TelemetryItem]')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 206]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if response.status_code == 200:
            deserialized = self._deserialize('TrackResponse', pipeline_response)

        if response.status_code == 206:
            deserialized = self._deserialize('TrackResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    track.metadata = {'url': '/track'}  # type: ignore
