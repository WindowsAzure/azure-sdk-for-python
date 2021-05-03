# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import TYPE_CHECKING

from azure.core.pipeline.transport._base import _format_url_section
from azure.farmbeats.core.rest import HttpRequest
from msrest import Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Dict, List, Optional

_SERIALIZER = Serializer()


def build_list_request(
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Returns a paginated list of weather data.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :keyword farmer_id: Farmer ID.
    :paramtype farmer_id: str
    :keyword boundary_id: Boundary ID.
    :paramtype boundary_id: str
    :keyword extension_id: ID of the weather extension.
    :paramtype extension_id: str
    :keyword weather_data_type: Type of weather data (forecast/historical).
    :paramtype weather_data_type: str
    :keyword granularity: Granularity of weather data (daily/hourly).
    :paramtype granularity: str
    :keyword start_date_time: Weather data start UTC date-time (inclusive), sample format: yyyy-MM-
     ddTHH:mm:ssZ.
    :paramtype start_date_time: ~datetime.datetime
    :keyword end_date_time: Weather data end UTC date-time (inclusive), sample format: yyyy-MM-
     ddTHH:mm:ssZ.
    :paramtype end_date_time: ~datetime.datetime
    :keyword max_page_size: Maximum number of items needed (inclusive).
     Minimum = 10, Maximum = 1000, Default value = 50.
    :paramtype max_page_size: int
    :keyword skip_token: Skip token for getting next set of results.
    :paramtype skip_token: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

    
            # response body for status code(s): 200
            response_body == {
                "$skipToken": "str (optional)",
                "nextLink": "str (optional)",
                "value": [
                    {
                        "boundaryId": "str",
                        "cloudCover": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "createdDateTime": "datetime (optional)",
                        "dateTime": "datetime",
                        "dewPoint": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "eTag": "str (optional)",
                        "extensionId": "str",
                        "extensionVersion": "str",
                        "farmerId": "str",
                        "granularity": "str",
                        "growingDegreeDay": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "id": "str (optional)",
                        "location": {
                            "latitude": "float",
                            "longitude": "float"
                        },
                        "modifiedDateTime": "datetime (optional)",
                        "precipitation": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "pressure": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "properties": {
                            "str": "object (optional)"
                        },
                        "relativeHumidity": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "soilMoisture": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "soilTemperature": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "temperature": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "unitSystemCode": "str (optional)",
                        "visibility": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "weatherDataType": "str",
                        "wetBulbTemperature": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "windChill": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "windDirection": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "windGust": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "windSpeed": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        }
                    }
                ]
            }

    """
    farmer_id = kwargs.pop('farmer_id')  # type: str
    boundary_id = kwargs.pop('boundary_id')  # type: str
    extension_id = kwargs.pop('extension_id')  # type: str
    weather_data_type = kwargs.pop('weather_data_type')  # type: str
    granularity = kwargs.pop('granularity')  # type: str
    start_date_time = kwargs.pop('start_date_time', None)  # type: Optional[datetime.datetime]
    end_date_time = kwargs.pop('end_date_time', None)  # type: Optional[datetime.datetime]
    max_page_size = kwargs.pop('max_page_size', 50)  # type: Optional[int]
    skip_token = kwargs.pop('skip_token', None)  # type: Optional[str]
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/weather')

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['farmerId'] = _SERIALIZER.query("farmer_id", farmer_id, 'str')
    query_parameters['boundaryId'] = _SERIALIZER.query("boundary_id", boundary_id, 'str')
    query_parameters['extensionId'] = _SERIALIZER.query("extension_id", extension_id, 'str', pattern=r'^[A-za-z]{3,50}[.][A-za-z]{3,100}$')
    query_parameters['weatherDataType'] = _SERIALIZER.query("weather_data_type", weather_data_type, 'str', max_length=50, min_length=0)
    query_parameters['granularity'] = _SERIALIZER.query("granularity", granularity, 'str', max_length=50, min_length=0)
    if start_date_time is not None:
        query_parameters['startDateTime'] = _SERIALIZER.query("start_date_time", start_date_time, 'iso-8601')
    if end_date_time is not None:
        query_parameters['endDateTime'] = _SERIALIZER.query("end_date_time", end_date_time, 'iso-8601')
    if max_page_size is not None:
        query_parameters['$maxPageSize'] = _SERIALIZER.query("max_page_size", max_page_size, 'int', maximum=1000, minimum=10)
    if skip_token is not None:
        query_parameters['$skipToken'] = _SERIALIZER.query("skip_token", skip_token, 'str')
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


def build_get_data_ingestion_job_details_request(
    job_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Get weather ingestion job.

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
                "boundaryId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endTime": "datetime (optional)",
                "extensionApiInput": {
                    "str": "object"
                },
                "extensionApiName": "str",
                "extensionDataProviderApiKey": "str (optional)",
                "extensionDataProviderAppId": "str (optional)",
                "extensionId": "str",
                "farmerId": "str",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "startTime": "datetime (optional)",
                "status": "str (optional)"
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/weather/ingest-data/{jobId}')
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


def build_create_data_ingestion_job_request_initial(
    job_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Create a weather data ingestion job.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param job_id: Job id supplied by user.
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
                "boundaryId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endTime": "datetime (optional)",
                "extensionApiInput": {
                    "str": "object"
                },
                "extensionApiName": "str",
                "extensionDataProviderApiKey": "str (optional)",
                "extensionDataProviderAppId": "str (optional)",
                "extensionId": "str",
                "farmerId": "str",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "startTime": "datetime (optional)",
                "status": "str (optional)"
            }

    
            # response body for status code(s): 202
            response_body == {
                "boundaryId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endTime": "datetime (optional)",
                "extensionApiInput": {
                    "str": "object"
                },
                "extensionApiName": "str",
                "extensionDataProviderApiKey": "str (optional)",
                "extensionDataProviderAppId": "str (optional)",
                "extensionId": "str",
                "farmerId": "str",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "startTime": "datetime (optional)",
                "status": "str (optional)"
            }

    """
    content_type = kwargs.pop("content_type", None)
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/weather/ingest-data/{jobId}')
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
        **kwargs
    )


def build_get_data_delete_job_details_request(
    job_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Get weather data delete job.

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
                "boundaryId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endDateTime": "datetime (optional)",
                "endTime": "datetime (optional)",
                "extensionId": "str",
                "farmerId": "str",
                "granularity": "str (optional)",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "startDateTime": "datetime (optional)",
                "startTime": "datetime (optional)",
                "status": "str (optional)",
                "weatherDataType": "str (optional)"
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/weather/delete-data/{jobId}')
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


def build_create_data_delete_job_request_initial(
    job_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Create a weather data delete job.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param job_id: Job Id supplied by end user.
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
                "boundaryId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endDateTime": "datetime (optional)",
                "endTime": "datetime (optional)",
                "extensionId": "str",
                "farmerId": "str",
                "granularity": "str (optional)",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "startDateTime": "datetime (optional)",
                "startTime": "datetime (optional)",
                "status": "str (optional)",
                "weatherDataType": "str (optional)"
            }

    
            # response body for status code(s): 202
            response_body == {
                "boundaryId": "str",
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endDateTime": "datetime (optional)",
                "endTime": "datetime (optional)",
                "extensionId": "str",
                "farmerId": "str",
                "granularity": "str (optional)",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "startDateTime": "datetime (optional)",
                "startTime": "datetime (optional)",
                "status": "str (optional)",
                "weatherDataType": "str (optional)"
            }

    """
    content_type = kwargs.pop("content_type", None)
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/weather/delete-data/{jobId}')
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
        **kwargs
    )

