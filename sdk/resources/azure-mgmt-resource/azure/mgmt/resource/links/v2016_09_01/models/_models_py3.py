# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import List, Optional

import msrest.serialization


class Operation(msrest.serialization.Model):
    """Microsoft.Resources operation.

    :param name: Operation name: {provider}/{resource}/{operation}.
    :type name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.resource.links.v2016_09_01.models.OperationDisplay
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        display: Optional["OperationDisplay"] = None,
        **kwargs
    ):
        super(Operation, self).__init__(**kwargs)
        self.name = name
        self.display = display


class OperationDisplay(msrest.serialization.Model):
    """The object that represents the operation.

    :param provider: Service provider: Microsoft.Resources.
    :type provider: str
    :param resource: Resource on which the operation is performed: Profile, endpoint, etc.
    :type resource: str
    :param operation: Operation type: Read, write, delete, etc.
    :type operation: str
    :param description: Description of the operation.
    :type description: str
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        provider: Optional[str] = None,
        resource: Optional[str] = None,
        operation: Optional[str] = None,
        description: Optional[str] = None,
        **kwargs
    ):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description


class OperationListResult(msrest.serialization.Model):
    """Result of the request to list Microsoft.Resources operations. It contains a list of operations and a URL link to get the next set of results.

    :param value: List of Microsoft.Resources operations.
    :type value: list[~azure.mgmt.resource.links.v2016_09_01.models.Operation]
    :param next_link: URL to get the next set of operation list results if there are any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["Operation"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(OperationListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class ResourceLink(msrest.serialization.Model):
    """The resource link.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The fully qualified ID of the resource link.
    :vartype id: str
    :ivar name: The name of the resource link.
    :vartype name: str
    :ivar type: The resource link object.
    :vartype type: object
    :param properties: Properties for resource link.
    :type properties: ~azure.mgmt.resource.links.v2016_09_01.models.ResourceLinkProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'object'},
        'properties': {'key': 'properties', 'type': 'ResourceLinkProperties'},
    }

    def __init__(
        self,
        *,
        properties: Optional["ResourceLinkProperties"] = None,
        **kwargs
    ):
        super(ResourceLink, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.properties = properties


class ResourceLinkFilter(msrest.serialization.Model):
    """Resource link filter.

    All required parameters must be populated in order to send to Azure.

    :param target_id: Required. The ID of the target resource.
    :type target_id: str
    """

    _validation = {
        'target_id': {'required': True},
    }

    _attribute_map = {
        'target_id': {'key': 'targetId', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        target_id: str,
        **kwargs
    ):
        super(ResourceLinkFilter, self).__init__(**kwargs)
        self.target_id = target_id


class ResourceLinkProperties(msrest.serialization.Model):
    """The resource link properties.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar source_id: The fully qualified ID of the source resource in the link.
    :vartype source_id: str
    :param target_id: Required. The fully qualified ID of the target resource in the link.
    :type target_id: str
    :param notes: Notes about the resource link.
    :type notes: str
    """

    _validation = {
        'source_id': {'readonly': True},
        'target_id': {'required': True},
    }

    _attribute_map = {
        'source_id': {'key': 'sourceId', 'type': 'str'},
        'target_id': {'key': 'targetId', 'type': 'str'},
        'notes': {'key': 'notes', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        target_id: str,
        notes: Optional[str] = None,
        **kwargs
    ):
        super(ResourceLinkProperties, self).__init__(**kwargs)
        self.source_id = None
        self.target_id = target_id
        self.notes = notes


class ResourceLinkResult(msrest.serialization.Model):
    """List of resource links.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. An array of resource links.
    :type value: list[~azure.mgmt.resource.links.v2016_09_01.models.ResourceLink]
    :ivar next_link: The URL to use for getting the next set of results.
    :vartype next_link: str
    """

    _validation = {
        'value': {'required': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ResourceLink]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: List["ResourceLink"],
        **kwargs
    ):
        super(ResourceLinkResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = None
