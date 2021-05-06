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
    from typing import Any, Dict, List, Optional, Union

_SERIALIZER = Serializer()


def build_create_request(
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Create a new relationship between entities.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :keyword json: The AtlasRelationship object containing the information for the relationship to
     be created.
    :paramtype json: Any
    :keyword content: The AtlasRelationship object containing the information for the relationship
     to be created.
    :paramtype content: Any
    :return: Returns an :class:`~azure.purview.catalog.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.catalog.core.rest.HttpRequest

    Example:
        .. code-block:: python

    
            # JSON input template you can fill out and use as your `json` input.
            json = {
                "createTime": "float (optional)",
                "createdBy": "str (optional)",
                "end1": {
                    "guid": "str (optional)",
                    "typeName": "str (optional)",
                    "uniqueAttributes": {
                        "str": "object (optional)"
                    }
                },
                "end2": {
                    "guid": "str (optional)",
                    "typeName": "str (optional)",
                    "uniqueAttributes": {
                        "str": "object (optional)"
                    }
                },
                "guid": "str (optional)",
                "homeId": "str (optional)",
                "label": "str (optional)",
                "provenanceType": "float (optional)",
                "status": "str (optional)",
                "updateTime": "float (optional)",
                "updatedBy": "str (optional)",
                "version": "float (optional)"
            }

    
            # response body for status code(s): 200
            response_body == {
                "createTime": "float (optional)",
                "createdBy": "str (optional)",
                "end1": {
                    "guid": "str (optional)",
                    "typeName": "str (optional)",
                    "uniqueAttributes": {
                        "str": "object (optional)"
                    }
                },
                "end2": {
                    "guid": "str (optional)",
                    "typeName": "str (optional)",
                    "uniqueAttributes": {
                        "str": "object (optional)"
                    }
                },
                "guid": "str (optional)",
                "homeId": "str (optional)",
                "label": "str (optional)",
                "provenanceType": "float (optional)",
                "status": "str (optional)",
                "updateTime": "float (optional)",
                "updatedBy": "str (optional)",
                "version": "float (optional)"
            }

    """
    content_type = kwargs.pop("content_type", None)
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/atlas/v2/relationship')

    # Construct headers
    header_parameters = kwargs.pop("headers", {})  # type: Dict[str, Any]
    if content_type is not None:
        header_parameters['Content-Type'] = _SERIALIZER.header("content_type", content_type, 'str')
    header_parameters['Accept'] = _SERIALIZER.header("accept", accept, 'str')

    return HttpRequest(
        method="POST",
        url=url,
        headers=header_parameters,
        **kwargs
    )


def build_update_request(
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Update an existing relationship between entities.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :keyword json: The AtlasRelationship object containing the information for the relationship to
     be created.
    :paramtype json: Any
    :keyword content: The AtlasRelationship object containing the information for the relationship
     to be created.
    :paramtype content: Any
    :return: Returns an :class:`~azure.purview.catalog.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.catalog.core.rest.HttpRequest

    Example:
        .. code-block:: python

    
            # JSON input template you can fill out and use as your `json` input.
            json = {
                "createTime": "float (optional)",
                "createdBy": "str (optional)",
                "end1": {
                    "guid": "str (optional)",
                    "typeName": "str (optional)",
                    "uniqueAttributes": {
                        "str": "object (optional)"
                    }
                },
                "end2": {
                    "guid": "str (optional)",
                    "typeName": "str (optional)",
                    "uniqueAttributes": {
                        "str": "object (optional)"
                    }
                },
                "guid": "str (optional)",
                "homeId": "str (optional)",
                "label": "str (optional)",
                "provenanceType": "float (optional)",
                "status": "str (optional)",
                "updateTime": "float (optional)",
                "updatedBy": "str (optional)",
                "version": "float (optional)"
            }

    
            # response body for status code(s): 200
            response_body == {
                "createTime": "float (optional)",
                "createdBy": "str (optional)",
                "end1": {
                    "guid": "str (optional)",
                    "typeName": "str (optional)",
                    "uniqueAttributes": {
                        "str": "object (optional)"
                    }
                },
                "end2": {
                    "guid": "str (optional)",
                    "typeName": "str (optional)",
                    "uniqueAttributes": {
                        "str": "object (optional)"
                    }
                },
                "guid": "str (optional)",
                "homeId": "str (optional)",
                "label": "str (optional)",
                "provenanceType": "float (optional)",
                "status": "str (optional)",
                "updateTime": "float (optional)",
                "updatedBy": "str (optional)",
                "version": "float (optional)"
            }

    """
    content_type = kwargs.pop("content_type", None)
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/atlas/v2/relationship')

    # Construct headers
    header_parameters = kwargs.pop("headers", {})  # type: Dict[str, Any]
    if content_type is not None:
        header_parameters['Content-Type'] = _SERIALIZER.header("content_type", content_type, 'str')
    header_parameters['Accept'] = _SERIALIZER.header("accept", accept, 'str')

    return HttpRequest(
        method="PUT",
        url=url,
        headers=header_parameters,
        **kwargs
    )


def build_get_request(
    guid,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Get relationship information between entities by its GUID.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param guid: The globally unique identifier of the relationship.
    :type guid: str
    :keyword extended_info: Limits whether includes extended information.
    :paramtype extended_info: bool
    :return: Returns an :class:`~azure.purview.catalog.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.catalog.core.rest.HttpRequest

    Example:
        .. code-block:: python

    
            # response body for status code(s): 200
            response_body == {
                "referredEntities": {
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
                "relationship": {
                    "createTime": "float (optional)",
                    "createdBy": "str (optional)",
                    "end1": {
                        "guid": "str (optional)",
                        "typeName": "str (optional)",
                        "uniqueAttributes": {
                            "str": "object (optional)"
                        }
                    },
                    "end2": {
                        "guid": "str (optional)",
                        "typeName": "str (optional)",
                        "uniqueAttributes": {
                            "str": "object (optional)"
                        }
                    },
                    "guid": "str (optional)",
                    "homeId": "str (optional)",
                    "label": "str (optional)",
                    "provenanceType": "float (optional)",
                    "status": "str (optional)",
                    "updateTime": "float (optional)",
                    "updatedBy": "str (optional)",
                    "version": "float (optional)"
                }
            }

    """
    extended_info = kwargs.pop('extended_info', None)  # type: Optional[bool]
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/atlas/v2/relationship/guid/{guid}')
    path_format_arguments = {
        'guid': _SERIALIZER.url("guid", guid, 'str', max_length=4096, min_length=1),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    if extended_info is not None:
        query_parameters['extendedInfo'] = _SERIALIZER.query("extended_info", extended_info, 'bool')

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


def build_delete_request(
    guid,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Delete a relationship between entities by its GUID.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param guid: The globally unique identifier of the relationship.
    :type guid: str
    :return: Returns an :class:`~azure.purview.catalog.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.catalog.core.rest.HttpRequest
    """

    # Construct URL
    url = kwargs.pop("template_url", '/atlas/v2/relationship/guid/{guid}')
    path_format_arguments = {
        'guid': _SERIALIZER.url("guid", guid, 'str', max_length=4096, min_length=1),
    }
    url = _format_url_section(url, **path_format_arguments)

    return HttpRequest(
        method="DELETE",
        url=url,
        **kwargs
    )

