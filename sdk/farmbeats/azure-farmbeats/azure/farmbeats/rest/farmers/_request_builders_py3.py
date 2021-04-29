# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from azure.core.pipeline.transport._base import _format_url_section
from azure.farmbeats.core.rest import HttpRequest
from msrest import Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

_SERIALIZER = Serializer()


def build_list_request(
    *,
    ids: Optional[List[str]] = None,
    names: Optional[List[str]] = None,
    property_filters: Optional[List[str]] = None,
    statuses: Optional[List[str]] = None,
    min_created_date_time: Optional[datetime.datetime] = None,
    max_created_date_time: Optional[datetime.datetime] = None,
    min_last_modified_date_time: Optional[datetime.datetime] = None,
    max_last_modified_date_time: Optional[datetime.datetime] = None,
    max_page_size: Optional[int] = 50,
    skip_token: Optional[str] = None,
    **kwargs: Any
) -> HttpRequest:
    """Returns a paginated list of farmer resources.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :keyword ids: Ids of the resource.
    :paramtype ids: list[str]
    :keyword names: Names of the resource.
    :paramtype names: list[str]
    :keyword property_filters: Filters on key-value pairs within the Properties object.
     eg. "{testkey} eq {testvalue}".
    :paramtype property_filters: list[str]
    :keyword statuses: Statuses of the resource.
    :paramtype statuses: list[str]
    :keyword min_created_date_time: Minimum creation date of resource (inclusive).
    :paramtype min_created_date_time: ~datetime.datetime
    :keyword max_created_date_time: Maximum creation date of resource (inclusive).
    :paramtype max_created_date_time: ~datetime.datetime
    :keyword min_last_modified_date_time: Minimum last modified date of resource (inclusive).
    :paramtype min_last_modified_date_time: ~datetime.datetime
    :keyword max_last_modified_date_time: Maximum last modified date of resource (inclusive).
    :paramtype max_last_modified_date_time: ~datetime.datetime
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
                        "createdDateTime": "datetime (optional)",
                        "description": "str (optional)",
                        "eTag": "str (optional)",
                        "id": "str (optional)",
                        "modifiedDateTime": "datetime (optional)",
                        "name": "str (optional)",
                        "properties": {
                            "str": "object (optional)"
                        },
                        "status": "str (optional)"
                    }
                ]
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers')

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    if ids is not None:
        query_parameters['ids'] = [_SERIALIZER.query("ids", q, 'str') if q is not None else '' for q in ids]
    if names is not None:
        query_parameters['names'] = [_SERIALIZER.query("names", q, 'str') if q is not None else '' for q in names]
    if property_filters is not None:
        query_parameters['propertyFilters'] = [_SERIALIZER.query("property_filters", q, 'str') if q is not None else '' for q in property_filters]
    if statuses is not None:
        query_parameters['statuses'] = [_SERIALIZER.query("statuses", q, 'str') if q is not None else '' for q in statuses]
    if min_created_date_time is not None:
        query_parameters['minCreatedDateTime'] = _SERIALIZER.query("min_created_date_time", min_created_date_time, 'iso-8601')
    if max_created_date_time is not None:
        query_parameters['maxCreatedDateTime'] = _SERIALIZER.query("max_created_date_time", max_created_date_time, 'iso-8601')
    if min_last_modified_date_time is not None:
        query_parameters['minLastModifiedDateTime'] = _SERIALIZER.query("min_last_modified_date_time", min_last_modified_date_time, 'iso-8601')
    if max_last_modified_date_time is not None:
        query_parameters['maxLastModifiedDateTime'] = _SERIALIZER.query("max_last_modified_date_time", max_last_modified_date_time, 'iso-8601')
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


def build_get_request(
    farmer_id: str,
    **kwargs: Any
) -> HttpRequest:
    """Gets a specified farmer resource.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: ID of the associated farmer.
    :type farmer_id: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

            # response body for status code(s): 200
            response_body == {
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "eTag": "str (optional)",
                "id": "str (optional)",
                "modifiedDateTime": "datetime (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "status": "str (optional)"
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
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


def build_create_or_update_request(
    farmer_id: str,
    *,
    json: Any = None,
    content: Any = None,
    **kwargs: Any
) -> HttpRequest:
    """Creates or updates a farmer resource.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: Id of the farmer resource.
    :type farmer_id: str
    :keyword json: Farmer resource payload to create or update.
    :paramtype json: Any
    :keyword content: Farmer resource payload to create or update.
    :paramtype content: Any
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

            # JSON input template you can fill out and use as your `json` input.
            json = {
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "eTag": "str (optional)",
                "id": "str (optional)",
                "modifiedDateTime": "datetime (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "status": "str (optional)"
            }

    """
    content_type = kwargs.pop("content_type", None)
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
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
        method="PATCH",
        url=url,
        params=query_parameters,
        headers=header_parameters,
        json=json,
        content=content,
        **kwargs
    )


def build_delete_request(
    farmer_id: str,
    **kwargs: Any
) -> HttpRequest:
    """Deletes a specified farmer resource.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: Id of farmer to be deleted.
    :type farmer_id: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest
    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['api-version'] = _SERIALIZER.query("api_version", api_version, 'str')

    # Construct headers
    header_parameters = kwargs.pop("headers", {})  # type: Dict[str, Any]
    header_parameters['Accept'] = _SERIALIZER.header("accept", accept, 'str')

    return HttpRequest(
        method="DELETE",
        url=url,
        params=query_parameters,
        headers=header_parameters,
        **kwargs
    )


def build_get_cascade_delete_job_details_request(
    job_id: str,
    **kwargs: Any
) -> HttpRequest:
    """Get a cascade delete job for specified farmer.

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
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endTime": "datetime (optional)",
                "farmerId": "str",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "resourceId": "str",
                "resourceType": "str",
                "startTime": "datetime (optional)",
                "status": "str (optional)"
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/cascade-delete/{jobId}')
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


def build_create_cascade_delete_job_request_initial(
    job_id: str,
    *,
    farmer_id: str,
    **kwargs: Any
) -> HttpRequest:
    """Create a cascade delete job for specified farmer.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param job_id: Job ID supplied by end user.
    :type job_id: str
    :keyword farmer_id: ID of the farmer to be deleted.
    :paramtype farmer_id: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

            # response body for status code(s): 202
            response_body == {
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "durationInSeconds": "str (optional)",
                "endTime": "datetime (optional)",
                "farmerId": "str",
                "id": "str (optional)",
                "lastActionDateTime": "datetime (optional)",
                "message": "str (optional)",
                "name": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "resourceId": "str",
                "resourceType": "str",
                "startTime": "datetime (optional)",
                "status": "str (optional)"
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/cascade-delete/{jobId}')
    path_format_arguments = {
        'jobId': _SERIALIZER.url("job_id", job_id, 'str'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['farmerId'] = _SERIALIZER.query("farmer_id", farmer_id, 'str')
    query_parameters['api-version'] = _SERIALIZER.query("api_version", api_version, 'str')

    # Construct headers
    header_parameters = kwargs.pop("headers", {})  # type: Dict[str, Any]
    header_parameters['Accept'] = _SERIALIZER.header("accept", accept, 'str')

    return HttpRequest(
        method="PUT",
        url=url,
        params=query_parameters,
        headers=header_parameters,
        **kwargs
    )

