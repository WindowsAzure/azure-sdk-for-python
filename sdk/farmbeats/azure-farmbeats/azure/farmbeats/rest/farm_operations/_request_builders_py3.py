# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import Any, Dict, List, Optional

from azure.core.pipeline.transport._base import _format_url_section
from azure.farmbeats.core.rest import HttpRequest
from msrest import Serializer

_SERIALIZER = Serializer()


def build_create_data_ingestion_job_request_initial(
    job_id: str,
    *,
    json: Any = None,
    content: Any = None,
    **kwargs: Any
) -> HttpRequest:
    """Create a farm operation data ingestion job.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param job_id: Job Id supplied by user.
    :type job_id: str
    :keyword json: Job parameters supplied by user.
    :paramtype json: Any
    :keyword content: Job parameters supplied by user.
    :paramtype content: Any
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

    
            # JSON input template you can fill out and use as your `json` input.
            json = {
                "authProviderId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endTime": "datetime (optional)",
                "farmerId": "str",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "operations": [
                    "str (optional)"
                ],
                "properties": {
                    "str": "object (optional)"
                },
                "startTime": "datetime (optional)",
                "startYear": "int",
                "status": "str (optional)"
            }

    
            # response body for status code(s): 202
            response_body == {
                "authProviderId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endTime": "datetime (optional)",
                "farmerId": "str",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "operations": [
                    "str (optional)"
                ],
                "properties": {
                    "str": "object (optional)"
                },
                "startTime": "datetime (optional)",
                "startYear": "int",
                "status": "str (optional)"
            }

    """
    content_type = kwargs.pop("content_type", None)
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farm-operations/ingest-data/{jobId}')
    path_format_arguments = {
        'jobId': _SERIALIZER.url("job_id", job_id, 'str'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['api-version'] = _SERIALIZER.query("api_version", api_version, 'str')

    # Construct headers
    header_parameters = kwargs.pop("headers", {})  # type: Dict[str, Any]
    if content_type is not None:
        header_parameters['Content-Type'] = _SERIALIZER.header("content_type", content_type, 'str')
    header_parameters['Accept'] = _SERIALIZER.header("accept", accept, 'str')

    return HttpRequest(
        method="PUT",
        url=url,
        params=query_parameters,
        headers=header_parameters,
        json=json,
        content=content,
        **kwargs
    )


def build_get_data_ingestion_job_details_request(
    job_id: str,
    **kwargs: Any
) -> HttpRequest:
    """Get a farm operation data ingestion job.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param job_id: Id of the job.
    :type job_id: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

    
            # response body for status code(s): 200
            response_body == {
                "authProviderId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endTime": "datetime (optional)",
                "farmerId": "str",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "operations": [
                    "str (optional)"
                ],
                "properties": {
                    "str": "object (optional)"
                },
                "startTime": "datetime (optional)",
                "startYear": "int",
                "status": "str (optional)"
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farm-operations/ingest-data/{jobId}')
    path_format_arguments = {
        'jobId': _SERIALIZER.url("job_id", job_id, 'str'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['api-version'] = _SERIALIZER.query("api_version", api_version, 'str')

    # Construct headers
    header_parameters = kwargs.pop("headers", {})  # type: Dict[str, Any]
    header_parameters['Accept'] = _SERIALIZER.header("accept", accept, 'str')

    return HttpRequest(
        method="GET",
        url=url,
        params=query_parameters,
        headers=header_parameters,
        **kwargs
    )

