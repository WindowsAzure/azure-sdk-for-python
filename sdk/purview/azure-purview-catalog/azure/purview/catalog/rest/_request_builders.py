# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING

from azure.core.pipeline.transport._base import _format_url_section
from azure.purview.catalog.core.rest import HttpRequest
from msrest import Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Dict, IO, List, Optional, Union

_SERIALIZER = Serializer()


def build_get_lineage_graph_request(
    guid,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Get lineage info of the entity specified by GUID.

    See https://aka.ms/azsdk/python/protocol/quickstart for how to incorporate this request builder into your code flow.

    :param guid: The globally unique identifier of the entity.
    :type guid: str
    :keyword direction: The direction of the lineage, which could be INPUT, OUTPUT or BOTH.
    :paramtype direction: str or ~azure.purview.catalog.models.Direction
    :keyword depth: The number of hops for lineage.
    :paramtype depth: int
    :keyword width: The number of max expanding width in lineage.
    :paramtype width: int
    :keyword include_parent: True to include the parent chain in the response.
    :paramtype include_parent: bool
    :keyword get_derived_lineage: True to include derived lineage in the response.
    :paramtype get_derived_lineage: bool
    :return: Returns an :class:`~azure.purview.catalog.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/protocol/quickstart for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.catalog.core.rest.HttpRequest

    Example:
        .. code-block:: python


            # response body for status code(s): 200
            response_body == {
                "baseEntityGuid": "str (optional)",
                "childrenCount": "int (optional)",
                "guidEntityMap": {
                    "str": {
                        "classificationNames": [
                            "str (optional)"
                        ],
                        "classifications": [
                            {
                                "entityGuid": "str (optional)",
                                "entityStatus": "str (optional)",
                                "removePropagationsOnEntityDelete": "bool (optional)",
                                "source": "str (optional)",
                                "sourceDetails": {
                                    "str": "object (optional)"
                                },
                                "validityPeriods": [
                                    {
                                        "endTime": "str (optional)",
                                        "startTime": "str (optional)",
                                        "timeZone": "str (optional)"
                                    }
                                ]
                            }
                        ],
                        "displayText": "str (optional)",
                        "guid": "str (optional)",
                        "meaningNames": [
                            "str (optional)"
                        ],
                        "meanings": [
                            {
                                "confidence": "int (optional)",
                                "createdBy": "str (optional)",
                                "description": "str (optional)",
                                "displayText": "str (optional)",
                                "expression": "str (optional)",
                                "relationGuid": "str (optional)",
                                "source": "str (optional)",
                                "status": "str (optional)",
                                "steward": "str (optional)",
                                "termGuid": "str (optional)"
                            }
                        ],
                        "status": "str (optional)"
                    }
                },
                "includeParent": "bool (optional)",
                "lineageDepth": "int (optional)",
                "lineageDirection": "str (optional)",
                "lineageWidth": "int (optional)",
                "parentRelations": [
                    {
                        "childEntityId": "str (optional)",
                        "parentEntityId": "str (optional)",
                        "relationshipId": "str (optional)"
                    }
                ],
                "relations": [
                    {
                        "fromEntityId": "str (optional)",
                        "relationshipId": "str (optional)",
                        "toEntityId": "str (optional)"
                    }
                ],
                "widthCounts": {
                    "str": {
                        "str": "object (optional)"
                    }
                }
            }

    """
    direction = kwargs.pop('direction')  # type: Union[str, "_models.Direction"]
    depth = kwargs.pop('depth', 3)  # type: Optional[int]
    width = kwargs.pop('width', 10)  # type: Optional[int]
    include_parent = kwargs.pop('include_parent', None)  # type: Optional[bool]
    get_derived_lineage = kwargs.pop('get_derived_lineage', None)  # type: Optional[bool]
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/atlas/v2/lineage/{guid}')
    path_format_arguments = {
        'guid': _SERIALIZER.url("guid", guid, 'str', max_length=4096, min_length=1),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    if depth is not None:
        query_parameters['depth'] = _SERIALIZER.query("depth", depth, 'int')
    if width is not None:
        query_parameters['width'] = _SERIALIZER.query("width", width, 'int')
    query_parameters['direction'] = _SERIALIZER.query("direction", direction, 'str')
    if include_parent is not None:
        query_parameters['includeParent'] = _SERIALIZER.query("include_parent", include_parent, 'bool')
    if get_derived_lineage is not None:
        query_parameters['getDerivedLineage'] = _SERIALIZER.query("get_derived_lineage", get_derived_lineage, 'bool')

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


def build_next_page_lineage_request(
    guid,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Return immediate next page lineage info about entity with pagination.

    See https://aka.ms/azsdk/python/protocol/quickstart for how to incorporate this request builder into your code flow.

    :param guid: The globally unique identifier of the entity.
    :type guid: str
    :keyword direction: The direction of the lineage, which could be INPUT, OUTPUT or BOTH.
    :paramtype direction: str or ~azure.purview.catalog.models.Direction
    :keyword get_derived_lineage: True to include derived lineage in the response.
    :paramtype get_derived_lineage: bool
    :keyword offset: The offset for pagination purpose.
    :paramtype offset: int
    :keyword limit: The page size - by default there is no paging.
    :paramtype limit: int
    :return: Returns an :class:`~azure.purview.catalog.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/protocol/quickstart for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.catalog.core.rest.HttpRequest

    Example:
        .. code-block:: python


            # response body for status code(s): 200
            response_body == {
                "baseEntityGuid": "str (optional)",
                "childrenCount": "int (optional)",
                "guidEntityMap": {
                    "str": {
                        "classificationNames": [
                            "str (optional)"
                        ],
                        "classifications": [
                            {
                                "entityGuid": "str (optional)",
                                "entityStatus": "str (optional)",
                                "removePropagationsOnEntityDelete": "bool (optional)",
                                "source": "str (optional)",
                                "sourceDetails": {
                                    "str": "object (optional)"
                                },
                                "validityPeriods": [
                                    {
                                        "endTime": "str (optional)",
                                        "startTime": "str (optional)",
                                        "timeZone": "str (optional)"
                                    }
                                ]
                            }
                        ],
                        "displayText": "str (optional)",
                        "guid": "str (optional)",
                        "meaningNames": [
                            "str (optional)"
                        ],
                        "meanings": [
                            {
                                "confidence": "int (optional)",
                                "createdBy": "str (optional)",
                                "description": "str (optional)",
                                "displayText": "str (optional)",
                                "expression": "str (optional)",
                                "relationGuid": "str (optional)",
                                "source": "str (optional)",
                                "status": "str (optional)",
                                "steward": "str (optional)",
                                "termGuid": "str (optional)"
                            }
                        ],
                        "status": "str (optional)"
                    }
                },
                "includeParent": "bool (optional)",
                "lineageDepth": "int (optional)",
                "lineageDirection": "str (optional)",
                "lineageWidth": "int (optional)",
                "parentRelations": [
                    {
                        "childEntityId": "str (optional)",
                        "parentEntityId": "str (optional)",
                        "relationshipId": "str (optional)"
                    }
                ],
                "relations": [
                    {
                        "fromEntityId": "str (optional)",
                        "relationshipId": "str (optional)",
                        "toEntityId": "str (optional)"
                    }
                ],
                "widthCounts": {
                    "str": {
                        "str": "object (optional)"
                    }
                }
            }

    """
    direction = kwargs.pop('direction')  # type: Union[str, "_models.Direction"]
    get_derived_lineage = kwargs.pop('get_derived_lineage', None)  # type: Optional[bool]
    offset = kwargs.pop('offset', None)  # type: Optional[int]
    limit = kwargs.pop('limit', None)  # type: Optional[int]
    api_version = "2021-05-01-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/lineage/{guid}/next/')
    path_format_arguments = {
        'guid': _SERIALIZER.url("guid", guid, 'str', max_length=4096, min_length=1),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['direction'] = _SERIALIZER.query("direction", direction, 'str')
    if get_derived_lineage is not None:
        query_parameters['getDerivedLineage'] = _SERIALIZER.query("get_derived_lineage", get_derived_lineage, 'bool')
    if offset is not None:
        query_parameters['offset'] = _SERIALIZER.query("offset", offset, 'int')
    if limit is not None:
        query_parameters['limit'] = _SERIALIZER.query("limit", limit, 'int')
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

