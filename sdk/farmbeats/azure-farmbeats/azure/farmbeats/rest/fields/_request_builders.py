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
    from typing import Any, IO, List, Optional

_SERIALIZER = Serializer()


def build_list_by_farmer_id_request(
    farmer_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Returns a paginated list of field resources under a particular farmer.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: Id of the associated farmer.
    :type farmer_id: str
    :keyword farm_ids: Farm Ids of the resource.
    :paramtype farm_ids: list[str]
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
                        "boundaryIds": [
                            "str (optional)"
                        ],
                        "createdDateTime": "datetime (optional)",
                        "description": "str (optional)",
                        "eTag": "str (optional)",
                        "farmId": "str (optional)",
                        "farmerId": "str (optional)",
                        "id": "str (optional)",
                        "modifiedDateTime": "datetime (optional)",
                        "name": "str (optional)",
                        "primaryBoundaryId": "str (optional)",
                        "properties": {
                            "str": "object (optional)"
                        },
                        "status": "str (optional)"
                    }
                ]
            }

    """
    farm_ids = kwargs.pop('farm_ids', None)  # type: Optional[List[str]]
    ids = kwargs.pop('ids', None)  # type: Optional[List[str]]
    names = kwargs.pop('names', None)  # type: Optional[List[str]]
    property_filters = kwargs.pop('property_filters', None)  # type: Optional[List[str]]
    statuses = kwargs.pop('statuses', None)  # type: Optional[List[str]]
    min_created_date_time = kwargs.pop('min_created_date_time', None)  # type: Optional[datetime.datetime]
    max_created_date_time = kwargs.pop('max_created_date_time', None)  # type: Optional[datetime.datetime]
    min_last_modified_date_time = kwargs.pop('min_last_modified_date_time', None)  # type: Optional[datetime.datetime]
    max_last_modified_date_time = kwargs.pop('max_last_modified_date_time', None)  # type: Optional[datetime.datetime]
    max_page_size = kwargs.pop('max_page_size', 50)  # type: Optional[int]
    skip_token = kwargs.pop('skip_token', None)  # type: Optional[str]
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}/fields')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    if farm_ids is not None:
        query_parameters['farmIds'] = [_SERIALIZER.query("farm_ids", q, 'str') if q is not None else '' for q in farm_ids]
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


def build_list_request(
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Returns a paginated list of field resources across all farmers.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :keyword farm_ids: Farm Ids of the resource.
    :paramtype farm_ids: list[str]
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
                        "boundaryIds": [
                            "str (optional)"
                        ],
                        "createdDateTime": "datetime (optional)",
                        "description": "str (optional)",
                        "eTag": "str (optional)",
                        "farmId": "str (optional)",
                        "farmerId": "str (optional)",
                        "id": "str (optional)",
                        "modifiedDateTime": "datetime (optional)",
                        "name": "str (optional)",
                        "primaryBoundaryId": "str (optional)",
                        "properties": {
                            "str": "object (optional)"
                        },
                        "status": "str (optional)"
                    }
                ]
            }

    """
    farm_ids = kwargs.pop('farm_ids', None)  # type: Optional[List[str]]
    ids = kwargs.pop('ids', None)  # type: Optional[List[str]]
    names = kwargs.pop('names', None)  # type: Optional[List[str]]
    property_filters = kwargs.pop('property_filters', None)  # type: Optional[List[str]]
    statuses = kwargs.pop('statuses', None)  # type: Optional[List[str]]
    min_created_date_time = kwargs.pop('min_created_date_time', None)  # type: Optional[datetime.datetime]
    max_created_date_time = kwargs.pop('max_created_date_time', None)  # type: Optional[datetime.datetime]
    min_last_modified_date_time = kwargs.pop('min_last_modified_date_time', None)  # type: Optional[datetime.datetime]
    max_last_modified_date_time = kwargs.pop('max_last_modified_date_time', None)  # type: Optional[datetime.datetime]
    max_page_size = kwargs.pop('max_page_size', 50)  # type: Optional[int]
    skip_token = kwargs.pop('skip_token', None)  # type: Optional[str]
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/fields')

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    if farm_ids is not None:
        query_parameters['farmIds'] = [_SERIALIZER.query("farm_ids", q, 'str') if q is not None else '' for q in farm_ids]
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
    farmer_id,  # type: str
    field_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Gets a specified field resource under a particular farmer.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: Id of the associated farmer.
    :type farmer_id: str
    :param field_id: Id of the field.
    :type field_id: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

    
            # response body for status code(s): 200
            response_body == {
                "boundaryIds": [
                    "str (optional)"
                ],
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "eTag": "str (optional)",
                "farmId": "str (optional)",
                "farmerId": "str (optional)",
                "id": "str (optional)",
                "modifiedDateTime": "datetime (optional)",
                "name": "str (optional)",
                "primaryBoundaryId": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "status": "str (optional)"
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}/fields/{fieldId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
        'fieldId': _SERIALIZER.url("field_id", field_id, 'str'),
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
    farmer_id,  # type: str
    field_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Creates or Updates a field resource under a particular farmer.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: Id of the associated farmer resource.
    :type farmer_id: str
    :param field_id: Id of the field resource.
    :type field_id: str
    :keyword json: Field resource payload to create or update.
    :paramtype json: Any
    :keyword content: Field resource payload to create or update.
    :paramtype content: Any
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

    
            # JSON input template you can fill out and use as your `json` input.
            json = {
                "boundaryIds": [
                    "str (optional)"
                ],
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "eTag": "str (optional)",
                "farmId": "str (optional)",
                "farmerId": "str (optional)",
                "id": "str (optional)",
                "modifiedDateTime": "datetime (optional)",
                "name": "str (optional)",
                "primaryBoundaryId": "str (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "status": "str (optional)"
            }

    
            # response body for status code(s): 200, 201
            response_body == {
                "boundaryIds": [
                    "str (optional)"
                ],
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "eTag": "str (optional)",
                "farmId": "str (optional)",
                "farmerId": "str (optional)",
                "id": "str (optional)",
                "modifiedDateTime": "datetime (optional)",
                "name": "str (optional)",
                "primaryBoundaryId": "str (optional)",
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
    url = kwargs.pop("template_url", '/farmers/{farmerId}/fields/{fieldId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
        'fieldId': _SERIALIZER.url("field_id", field_id, 'str'),
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
        **kwargs
    )


def build_delete_request(
    farmer_id,  # type: str
    field_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Deletes a specified field resource under a particular farmer.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: Id of the farmer.
    :type farmer_id: str
    :param field_id: Id of the field.
    :type field_id: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest
    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}/fields/{fieldId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
        'fieldId': _SERIALIZER.url("field_id", field_id, 'str'),
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
    job_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Get a cascade delete job for specified field.

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
    url = kwargs.pop("template_url", '/fields/cascade-delete/{jobId}')
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
    job_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Create a cascade delete job for specified field.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param job_id: Job ID supplied by end user.
    :type job_id: str
    :keyword farmer_id: ID of the associated farmer.
    :paramtype farmer_id: str
    :keyword field_id: ID of the field to be deleted.
    :paramtype field_id: str
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
    farmer_id = kwargs.pop('farmer_id')  # type: str
    field_id = kwargs.pop('field_id')  # type: str
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/fields/cascade-delete/{jobId}')
    path_format_arguments = {
        'jobId': _SERIALIZER.url("job_id", job_id, 'str'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['farmerId'] = _SERIALIZER.query("farmer_id", farmer_id, 'str')
    query_parameters['fieldId'] = _SERIALIZER.query("field_id", field_id, 'str')
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

