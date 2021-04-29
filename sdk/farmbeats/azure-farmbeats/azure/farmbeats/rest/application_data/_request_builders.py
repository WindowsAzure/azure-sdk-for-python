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
    """Returns a paginated list of application data resources under a particular farm.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: ID of the associated farmer.
    :type farmer_id: str
    :keyword min_avg_material: Minimum average amount of material applied during the application
     (inclusive).
    :paramtype min_avg_material: float
    :keyword max_avg_material: Maximum average amount of material applied during the application
     (inclusive).
    :paramtype max_avg_material: float
    :keyword min_total_material: Minimum total amount of material applied during the application
     (inclusive).
    :paramtype min_total_material: float
    :keyword max_total_material: Maximum total amount of material applied during the application
     (inclusive).
    :paramtype max_total_material: float
    :keyword sources: Sources of the operation data.
    :paramtype sources: list[str]
    :keyword associated_boundary_ids: Boundary IDs associated with operation data.
    :paramtype associated_boundary_ids: list[str]
    :keyword operation_boundary_ids: Operation boundary IDs associated with operation data.
    :paramtype operation_boundary_ids: list[str]
    :keyword min_operation_start_date_time: Minimum start date-time of the operation data, sample
     format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype min_operation_start_date_time: ~datetime.datetime
    :keyword max_operation_start_date_time: Maximum start date-time of the operation data, sample
     format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype max_operation_start_date_time: ~datetime.datetime
    :keyword min_operation_end_date_time: Minimum end date-time of the operation data, sample
     format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype min_operation_end_date_time: ~datetime.datetime
    :keyword max_operation_end_date_time: Maximum end date-time of the operation data, sample
     format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype max_operation_end_date_time: ~datetime.datetime
    :keyword min_operation_modified_date_time: Minimum modified date-time of the operation data,
     sample format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype min_operation_modified_date_time: ~datetime.datetime
    :keyword max_operation_modified_date_time: Maximum modified date-time of the operation data,
     sample format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype max_operation_modified_date_time: ~datetime.datetime
    :keyword min_area: Minimum area for which operation was applied (inclusive).
    :paramtype min_area: float
    :keyword max_area: Maximum area for which operation was applied (inclusive).
    :paramtype max_area: float
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
                        "applicationProductDetails": [
                            {
                                "avgMaterial": {
                                    "unit": "str (optional)",
                                    "value": "float (optional)"
                                },
                                "isCarrier": "bool (optional). Default value is False",
                                "productName": "str (optional)",
                                "totalMaterial": {
                                    "unit": "str (optional)",
                                    "value": "float (optional)"
                                }
                            }
                        ],
                        "area": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "associatedBoundaryId": "str (optional)",
                        "attachmentsLink": "str (optional)",
                        "avgMaterial": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "createdDateTime": "datetime (optional)",
                        "description": "str (optional)",
                        "eTag": "str (optional)",
                        "farmerId": "str (optional)",
                        "id": "str (optional)",
                        "modifiedDateTime": "datetime (optional)",
                        "name": "str (optional)",
                        "operationBoundaryId": "str (optional)",
                        "operationEndDateTime": "datetime (optional)",
                        "operationModifiedDateTime": "datetime (optional)",
                        "operationStartDateTime": "datetime (optional)",
                        "properties": {
                            "str": "object (optional)"
                        },
                        "source": "str (optional)",
                        "status": "str (optional)",
                        "totalMaterial": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        }
                    }
                ]
            }

    """
    min_avg_material = kwargs.pop('min_avg_material', None)  # type: Optional[float]
    max_avg_material = kwargs.pop('max_avg_material', None)  # type: Optional[float]
    min_total_material = kwargs.pop('min_total_material', None)  # type: Optional[float]
    max_total_material = kwargs.pop('max_total_material', None)  # type: Optional[float]
    sources = kwargs.pop('sources', None)  # type: Optional[List[str]]
    associated_boundary_ids = kwargs.pop('associated_boundary_ids', None)  # type: Optional[List[str]]
    operation_boundary_ids = kwargs.pop('operation_boundary_ids', None)  # type: Optional[List[str]]
    min_operation_start_date_time = kwargs.pop('min_operation_start_date_time', None)  # type: Optional[datetime.datetime]
    max_operation_start_date_time = kwargs.pop('max_operation_start_date_time', None)  # type: Optional[datetime.datetime]
    min_operation_end_date_time = kwargs.pop('min_operation_end_date_time', None)  # type: Optional[datetime.datetime]
    max_operation_end_date_time = kwargs.pop('max_operation_end_date_time', None)  # type: Optional[datetime.datetime]
    min_operation_modified_date_time = kwargs.pop('min_operation_modified_date_time', None)  # type: Optional[datetime.datetime]
    max_operation_modified_date_time = kwargs.pop('max_operation_modified_date_time', None)  # type: Optional[datetime.datetime]
    min_area = kwargs.pop('min_area', None)  # type: Optional[float]
    max_area = kwargs.pop('max_area', None)  # type: Optional[float]
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
    url = kwargs.pop("template_url", '/farmers/{farmerId}/application-data')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    if min_avg_material is not None:
        query_parameters['minAvgMaterial'] = _SERIALIZER.query("min_avg_material", min_avg_material, 'float')
    if max_avg_material is not None:
        query_parameters['maxAvgMaterial'] = _SERIALIZER.query("max_avg_material", max_avg_material, 'float')
    if min_total_material is not None:
        query_parameters['minTotalMaterial'] = _SERIALIZER.query("min_total_material", min_total_material, 'float')
    if max_total_material is not None:
        query_parameters['maxTotalMaterial'] = _SERIALIZER.query("max_total_material", max_total_material, 'float')
    if sources is not None:
        query_parameters['sources'] = [_SERIALIZER.query("sources", q, 'str') if q is not None else '' for q in sources]
    if associated_boundary_ids is not None:
        query_parameters['associatedBoundaryIds'] = [_SERIALIZER.query("associated_boundary_ids", q, 'str') if q is not None else '' for q in associated_boundary_ids]
    if operation_boundary_ids is not None:
        query_parameters['operationBoundaryIds'] = [_SERIALIZER.query("operation_boundary_ids", q, 'str') if q is not None else '' for q in operation_boundary_ids]
    if min_operation_start_date_time is not None:
        query_parameters['minOperationStartDateTime'] = _SERIALIZER.query("min_operation_start_date_time", min_operation_start_date_time, 'iso-8601')
    if max_operation_start_date_time is not None:
        query_parameters['maxOperationStartDateTime'] = _SERIALIZER.query("max_operation_start_date_time", max_operation_start_date_time, 'iso-8601')
    if min_operation_end_date_time is not None:
        query_parameters['minOperationEndDateTime'] = _SERIALIZER.query("min_operation_end_date_time", min_operation_end_date_time, 'iso-8601')
    if max_operation_end_date_time is not None:
        query_parameters['maxOperationEndDateTime'] = _SERIALIZER.query("max_operation_end_date_time", max_operation_end_date_time, 'iso-8601')
    if min_operation_modified_date_time is not None:
        query_parameters['minOperationModifiedDateTime'] = _SERIALIZER.query("min_operation_modified_date_time", min_operation_modified_date_time, 'iso-8601')
    if max_operation_modified_date_time is not None:
        query_parameters['maxOperationModifiedDateTime'] = _SERIALIZER.query("max_operation_modified_date_time", max_operation_modified_date_time, 'iso-8601')
    if min_area is not None:
        query_parameters['minArea'] = _SERIALIZER.query("min_area", min_area, 'float')
    if max_area is not None:
        query_parameters['maxArea'] = _SERIALIZER.query("max_area", max_area, 'float')
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
    """Returns a paginated list of application data resources across all farmers.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :keyword min_avg_material: Minimum average amount of material applied during the application
     (inclusive).
    :paramtype min_avg_material: float
    :keyword max_avg_material: Maximum average amount of material applied during the application
     (inclusive).
    :paramtype max_avg_material: float
    :keyword min_total_material: Minimum total amount of material applied during the application
     (inclusive).
    :paramtype min_total_material: float
    :keyword max_total_material: Maximum total amount of material applied during the application
     (inclusive).
    :paramtype max_total_material: float
    :keyword sources: Sources of the operation data.
    :paramtype sources: list[str]
    :keyword associated_boundary_ids: Boundary IDs associated with operation data.
    :paramtype associated_boundary_ids: list[str]
    :keyword operation_boundary_ids: Operation boundary IDs associated with operation data.
    :paramtype operation_boundary_ids: list[str]
    :keyword min_operation_start_date_time: Minimum start date-time of the operation data, sample
     format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype min_operation_start_date_time: ~datetime.datetime
    :keyword max_operation_start_date_time: Maximum start date-time of the operation data, sample
     format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype max_operation_start_date_time: ~datetime.datetime
    :keyword min_operation_end_date_time: Minimum end date-time of the operation data, sample
     format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype min_operation_end_date_time: ~datetime.datetime
    :keyword max_operation_end_date_time: Maximum end date-time of the operation data, sample
     format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype max_operation_end_date_time: ~datetime.datetime
    :keyword min_operation_modified_date_time: Minimum modified date-time of the operation data,
     sample format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype min_operation_modified_date_time: ~datetime.datetime
    :keyword max_operation_modified_date_time: Maximum modified date-time of the operation data,
     sample format: yyyy-MM-ddTHH:mm:ssZ (inclusive).
    :paramtype max_operation_modified_date_time: ~datetime.datetime
    :keyword min_area: Minimum area for which operation was applied (inclusive).
    :paramtype min_area: float
    :keyword max_area: Maximum area for which operation was applied (inclusive).
    :paramtype max_area: float
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
                        "applicationProductDetails": [
                            {
                                "avgMaterial": {
                                    "unit": "str (optional)",
                                    "value": "float (optional)"
                                },
                                "isCarrier": "bool (optional). Default value is False",
                                "productName": "str (optional)",
                                "totalMaterial": {
                                    "unit": "str (optional)",
                                    "value": "float (optional)"
                                }
                            }
                        ],
                        "area": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "associatedBoundaryId": "str (optional)",
                        "attachmentsLink": "str (optional)",
                        "avgMaterial": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "createdDateTime": "datetime (optional)",
                        "description": "str (optional)",
                        "eTag": "str (optional)",
                        "farmerId": "str (optional)",
                        "id": "str (optional)",
                        "modifiedDateTime": "datetime (optional)",
                        "name": "str (optional)",
                        "operationBoundaryId": "str (optional)",
                        "operationEndDateTime": "datetime (optional)",
                        "operationModifiedDateTime": "datetime (optional)",
                        "operationStartDateTime": "datetime (optional)",
                        "properties": {
                            "str": "object (optional)"
                        },
                        "source": "str (optional)",
                        "status": "str (optional)",
                        "totalMaterial": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        }
                    }
                ]
            }

    """
    min_avg_material = kwargs.pop('min_avg_material', None)  # type: Optional[float]
    max_avg_material = kwargs.pop('max_avg_material', None)  # type: Optional[float]
    min_total_material = kwargs.pop('min_total_material', None)  # type: Optional[float]
    max_total_material = kwargs.pop('max_total_material', None)  # type: Optional[float]
    sources = kwargs.pop('sources', None)  # type: Optional[List[str]]
    associated_boundary_ids = kwargs.pop('associated_boundary_ids', None)  # type: Optional[List[str]]
    operation_boundary_ids = kwargs.pop('operation_boundary_ids', None)  # type: Optional[List[str]]
    min_operation_start_date_time = kwargs.pop('min_operation_start_date_time', None)  # type: Optional[datetime.datetime]
    max_operation_start_date_time = kwargs.pop('max_operation_start_date_time', None)  # type: Optional[datetime.datetime]
    min_operation_end_date_time = kwargs.pop('min_operation_end_date_time', None)  # type: Optional[datetime.datetime]
    max_operation_end_date_time = kwargs.pop('max_operation_end_date_time', None)  # type: Optional[datetime.datetime]
    min_operation_modified_date_time = kwargs.pop('min_operation_modified_date_time', None)  # type: Optional[datetime.datetime]
    max_operation_modified_date_time = kwargs.pop('max_operation_modified_date_time', None)  # type: Optional[datetime.datetime]
    min_area = kwargs.pop('min_area', None)  # type: Optional[float]
    max_area = kwargs.pop('max_area', None)  # type: Optional[float]
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
    url = kwargs.pop("template_url", '/application-data')

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    if min_avg_material is not None:
        query_parameters['minAvgMaterial'] = _SERIALIZER.query("min_avg_material", min_avg_material, 'float')
    if max_avg_material is not None:
        query_parameters['maxAvgMaterial'] = _SERIALIZER.query("max_avg_material", max_avg_material, 'float')
    if min_total_material is not None:
        query_parameters['minTotalMaterial'] = _SERIALIZER.query("min_total_material", min_total_material, 'float')
    if max_total_material is not None:
        query_parameters['maxTotalMaterial'] = _SERIALIZER.query("max_total_material", max_total_material, 'float')
    if sources is not None:
        query_parameters['sources'] = [_SERIALIZER.query("sources", q, 'str') if q is not None else '' for q in sources]
    if associated_boundary_ids is not None:
        query_parameters['associatedBoundaryIds'] = [_SERIALIZER.query("associated_boundary_ids", q, 'str') if q is not None else '' for q in associated_boundary_ids]
    if operation_boundary_ids is not None:
        query_parameters['operationBoundaryIds'] = [_SERIALIZER.query("operation_boundary_ids", q, 'str') if q is not None else '' for q in operation_boundary_ids]
    if min_operation_start_date_time is not None:
        query_parameters['minOperationStartDateTime'] = _SERIALIZER.query("min_operation_start_date_time", min_operation_start_date_time, 'iso-8601')
    if max_operation_start_date_time is not None:
        query_parameters['maxOperationStartDateTime'] = _SERIALIZER.query("max_operation_start_date_time", max_operation_start_date_time, 'iso-8601')
    if min_operation_end_date_time is not None:
        query_parameters['minOperationEndDateTime'] = _SERIALIZER.query("min_operation_end_date_time", min_operation_end_date_time, 'iso-8601')
    if max_operation_end_date_time is not None:
        query_parameters['maxOperationEndDateTime'] = _SERIALIZER.query("max_operation_end_date_time", max_operation_end_date_time, 'iso-8601')
    if min_operation_modified_date_time is not None:
        query_parameters['minOperationModifiedDateTime'] = _SERIALIZER.query("min_operation_modified_date_time", min_operation_modified_date_time, 'iso-8601')
    if max_operation_modified_date_time is not None:
        query_parameters['maxOperationModifiedDateTime'] = _SERIALIZER.query("max_operation_modified_date_time", max_operation_modified_date_time, 'iso-8601')
    if min_area is not None:
        query_parameters['minArea'] = _SERIALIZER.query("min_area", min_area, 'float')
    if max_area is not None:
        query_parameters['maxArea'] = _SERIALIZER.query("max_area", max_area, 'float')
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
    application_data_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Get a specified application data resource under a particular farmer.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: ID of the associated farmer resource.
    :type farmer_id: str
    :param application_data_id: ID of the application data resource.
    :type application_data_id: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

            # response body for status code(s): 200
            response_body == {
                "applicationProductDetails": [
                    {
                        "avgMaterial": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "isCarrier": "bool (optional). Default value is False",
                        "productName": "str (optional)",
                        "totalMaterial": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        }
                    }
                ],
                "area": {
                    "unit": "str (optional)",
                    "value": "float (optional)"
                },
                "associatedBoundaryId": "str (optional)",
                "attachmentsLink": "str (optional)",
                "avgMaterial": {
                    "unit": "str (optional)",
                    "value": "float (optional)"
                },
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "eTag": "str (optional)",
                "farmerId": "str (optional)",
                "id": "str (optional)",
                "modifiedDateTime": "datetime (optional)",
                "name": "str (optional)",
                "operationBoundaryId": "str (optional)",
                "operationEndDateTime": "datetime (optional)",
                "operationModifiedDateTime": "datetime (optional)",
                "operationStartDateTime": "datetime (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "source": "str (optional)",
                "status": "str (optional)",
                "totalMaterial": {
                    "unit": "str (optional)",
                    "value": "float (optional)"
                }
            }

    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}/application-data/{applicationDataId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
        'applicationDataId': _SERIALIZER.url("application_data_id", application_data_id, 'str'),
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
    application_data_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Creates or updates an application data resource under a particular farmer.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: ID of the associated farmer.
    :type farmer_id: str
    :param application_data_id: ID of the application data resource.
    :type application_data_id: str
    :keyword json: Application data resource payload to create or update.
    :paramtype json: Any
    :keyword content: Application data resource payload to create or update.
    :paramtype content: Any
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest

    Example:
        .. code-block:: python

            # JSON input template you can fill out and use as your `json` input.
            json = {
                "applicationProductDetails": [
                    {
                        "avgMaterial": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        },
                        "isCarrier": "bool (optional). Default value is False",
                        "productName": "str (optional)",
                        "totalMaterial": {
                            "unit": "str (optional)",
                            "value": "float (optional)"
                        }
                    }
                ],
                "area": {
                    "unit": "str (optional)",
                    "value": "float (optional)"
                },
                "associatedBoundaryId": "str (optional)",
                "attachmentsLink": "str (optional)",
                "avgMaterial": {
                    "unit": "str (optional)",
                    "value": "float (optional)"
                },
                "createdDateTime": "datetime (optional)",
                "description": "str (optional)",
                "eTag": "str (optional)",
                "farmerId": "str (optional)",
                "id": "str (optional)",
                "modifiedDateTime": "datetime (optional)",
                "name": "str (optional)",
                "operationBoundaryId": "str (optional)",
                "operationEndDateTime": "datetime (optional)",
                "operationModifiedDateTime": "datetime (optional)",
                "operationStartDateTime": "datetime (optional)",
                "properties": {
                    "str": "object (optional)"
                },
                "source": "str (optional)",
                "status": "str (optional)",
                "totalMaterial": {
                    "unit": "str (optional)",
                    "value": "float (optional)"
                }
            }

    """
    content_type = kwargs.pop("content_type", None)
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}/application-data/{applicationDataId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
        'applicationDataId': _SERIALIZER.url("application_data_id", application_data_id, 'str'),
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
    application_data_id,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Deletes a specified application data resource under a particular farmer.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param farmer_id: ID of the associated farmer resource.
    :type farmer_id: str
    :param application_data_id: ID of the application data.
    :type application_data_id: str
    :return: Returns an :class:`~azure.farmbeats.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.farmbeats.core.rest.HttpRequest
    """
    api_version = "2021-03-31-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/farmers/{farmerId}/application-data/{applicationDataId}')
    path_format_arguments = {
        'farmerId': _SERIALIZER.url("farmer_id", farmer_id, 'str'),
        'applicationDataId': _SERIALIZER.url("application_data_id", application_data_id, 'str'),
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

