# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING

from azure.core.pipeline.transport._base import _format_url_section
from azure.purview.scanning.core.rest import HttpRequest
from msrest import Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional, Union

_SERIALIZER = Serializer()


def build_get_request(
    classification_rule_name,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Get a classification rule.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param classification_rule_name:
    :type classification_rule_name: str
    :return: Returns an :class:`~azure.purview.scanning.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.scanning.core.rest.HttpRequest
    """
    api_version = "2018-12-01-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/classificationrules/{classificationRuleName}')
    path_format_arguments = {
        'classificationRuleName': _SERIALIZER.url("classification_rule_name", classification_rule_name, 'str'),
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
    classification_rule_name,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Creates or Updates a classification rule.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param classification_rule_name:
    :type classification_rule_name: str
    :keyword json:
    :paramtype json: Any
    :keyword content:
    :paramtype content: Any
    :return: Returns an :class:`~azure.purview.scanning.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.scanning.core.rest.HttpRequest

    Example:
        .. code-block:: python

            # JSON input template you can fill out and use as your `json` input.
            json = {
                "kind": "str"
            }
    """
    content_type = kwargs.pop("content_type", None)
    api_version = "2018-12-01-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/classificationrules/{classificationRuleName}')
    path_format_arguments = {
        'classificationRuleName': _SERIALIZER.url("classification_rule_name", classification_rule_name, 'str'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['api-version'] = _SERIALIZER.query("api_version", api_version, 'str')

    # Construct headers
    header_parameters = kwargs.pop("headers", {})  # type: Dict[str, Any]
    header_parameters['Accept'] = _SERIALIZER.header("accept", accept, 'str')
    if content_type is not None:
        header_parameters['Content-Type'] = _SERIALIZER.header("content_type", content_type, 'str')

    return HttpRequest(
        method="PUT",
        url=url,
        params=query_parameters,
        headers=header_parameters,
        **kwargs
    )


def build_delete_request(
    classification_rule_name,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Deletes a classification rule.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param classification_rule_name:
    :type classification_rule_name: str
    :return: Returns an :class:`~azure.purview.scanning.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.scanning.core.rest.HttpRequest
    """
    api_version = "2018-12-01-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/classificationrules/{classificationRuleName}')
    path_format_arguments = {
        'classificationRuleName': _SERIALIZER.url("classification_rule_name", classification_rule_name, 'str'),
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


def build_list_all_request(
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """List classification rules in Account.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :return: Returns an :class:`~azure.purview.scanning.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.scanning.core.rest.HttpRequest
    """
    api_version = "2018-12-01-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/classificationrules')

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


def build_list_versions_by_classification_rule_name_request(
    classification_rule_name,  # type: str
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Lists the rule versions of a classification rule.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param classification_rule_name:
    :type classification_rule_name: str
    :return: Returns an :class:`~azure.purview.scanning.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.scanning.core.rest.HttpRequest
    """
    api_version = "2018-12-01-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/classificationrules/{classificationRuleName}/versions')
    path_format_arguments = {
        'classificationRuleName': _SERIALIZER.url("classification_rule_name", classification_rule_name, 'str'),
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


def build_tag_classification_version_request(
    classification_rule_name,  # type: str
    classification_rule_version,  # type: int
    **kwargs  # type: Any
):
    # type: (...) -> HttpRequest
    """Sets Classification Action on a specific classification rule version.

    See https://aka.ms/azsdk/python/llcwiki for how to incorporate this request builder into your code flow.

    :param classification_rule_name:
    :type classification_rule_name: str
    :param classification_rule_version:
    :type classification_rule_version: int
    :keyword action:
    :paramtype action: str or ~azure.purview.scanning.models.ClassificationAction
    :return: Returns an :class:`~azure.purview.scanning.core.rest.HttpRequest` that you will pass to the client's `send_request` method.
     See https://aka.ms/azsdk/python/llcwiki for how to incorporate this response into your code flow.
    :rtype: ~azure.purview.scanning.core.rest.HttpRequest
    """
    action = kwargs.pop('action')  # type: Union[str, "_models.ClassificationAction"]
    api_version = "2018-12-01-preview"
    accept = "application/json"

    # Construct URL
    url = kwargs.pop("template_url", '/classificationrules/{classificationRuleName}/versions/{classificationRuleVersion}/:tag')
    path_format_arguments = {
        'classificationRuleName': _SERIALIZER.url("classification_rule_name", classification_rule_name, 'str'),
        'classificationRuleVersion': _SERIALIZER.url("classification_rule_version", classification_rule_version, 'int'),
    }
    url = _format_url_section(url, **path_format_arguments)

    # Construct parameters
    query_parameters = kwargs.pop("params", {})  # type: Dict[str, Any]
    query_parameters['action'] = _SERIALIZER.query("action", action, 'str')
    query_parameters['api-version'] = _SERIALIZER.query("api_version", api_version, 'str')

    # Construct headers
    header_parameters = kwargs.pop("headers", {})  # type: Dict[str, Any]
    header_parameters['Accept'] = _SERIALIZER.header("accept", accept, 'str')

    return HttpRequest(
        method="POST",
        url=url,
        params=query_parameters,
        headers=header_parameters,
        **kwargs
    )

