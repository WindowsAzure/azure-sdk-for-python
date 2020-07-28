# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import msrest.serialization


class PrivateLinkScopesResource(msrest.serialization.Model):
    """An azure resource object.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param location: Required. Resource location.
    :type location: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkScopesResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = kwargs['location']
        self.tags = kwargs.get('tags', None)


class AzureMonitorPrivateLinkScope(PrivateLinkScopesResource):
    """An Azure Monitor PrivateLinkScope definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param location: Required. Resource location.
    :type location: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :ivar provisioning_state: Current state of this PrivateLinkScope: whether or not is has been
     provisioned within the resource group it is defined. Users cannot change this value but are
     able to read from it. Values will include Provisioning ,Succeeded, Canceled and Failed.
    :vartype provisioning_state: str
    :ivar private_endpoint_connections: List of private endpoint connections.
    :vartype private_endpoint_connections: list[~$(python-base-
     namespace).v2019_10_17.models.PrivateEndpointConnection]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'private_endpoint_connections': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'private_endpoint_connections': {'key': 'properties.privateEndpointConnections', 'type': '[PrivateEndpointConnection]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AzureMonitorPrivateLinkScope, self).__init__(**kwargs)
        self.provisioning_state = None
        self.private_endpoint_connections = None


class AzureMonitorPrivateLinkScopeListResult(msrest.serialization.Model):
    """Describes the list of Azure Monitor PrivateLinkScope resources.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. List of Azure Monitor PrivateLinkScope definitions.
    :type value: list[~$(python-base-namespace).v2019_10_17.models.AzureMonitorPrivateLinkScope]
    :param next_link: The URI to get the next set of Azure Monitor PrivateLinkScope definitions if
     too many PrivateLinkScopes where returned in the result set.
    :type next_link: str
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[AzureMonitorPrivateLinkScope]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AzureMonitorPrivateLinkScopeListResult, self).__init__(**kwargs)
        self.value = kwargs['value']
        self.next_link = kwargs.get('next_link', None)


class ErrorAdditionalInfo(msrest.serialization.Model):
    """The resource management error additional info.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar type: The additional info type.
    :vartype type: str
    :ivar info: The additional info.
    :vartype info: object
    """

    _validation = {
        'type': {'readonly': True},
        'info': {'readonly': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'info': {'key': 'info', 'type': 'object'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorAdditionalInfo, self).__init__(**kwargs)
        self.type = None
        self.info = None


class ErrorResponse(msrest.serialization.Model):
    """Describes the format of Error response.

    :param code: Error code.
    :type code: str
    :param message: Error message indicating why the operation failed.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)


class ErrorResponseCommon(ErrorResponse):
    """The resource management error response.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param code: Error code.
    :type code: str
    :param message: Error message indicating why the operation failed.
    :type message: str
    :ivar details: The error details.
    :vartype details: list[~$(python-base-namespace).v2019_10_17.models.ErrorResponseCommon]
    :ivar additional_info: The error additional info.
    :vartype additional_info: list[~$(python-base-
     namespace).v2019_10_17.models.ErrorAdditionalInfo]
    """

    _validation = {
        'details': {'readonly': True},
        'additional_info': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorResponseCommon]'},
        'additional_info': {'key': 'additionalInfo', 'type': '[ErrorAdditionalInfo]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponseCommon, self).__init__(**kwargs)
        self.details = None
        self.additional_info = None


class OperationStatus(msrest.serialization.Model):
    """The status of operation.

    :param id: The operation Id.
    :type id: str
    :param name: The operation name.
    :type name: str
    :param start_time: Start time of the job in standard ISO8601 format.
    :type start_time: ~datetime.datetime
    :param end_time: End time of the job in standard ISO8601 format.
    :type end_time: ~datetime.datetime
    :param status: The status of the operation.
    :type status: str
    :param error: The error detail of the operation if any.
    :type error: ~$(python-base-namespace).v2019_10_17.models.ErrorResponseCommon
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'status': {'key': 'status', 'type': 'str'},
        'error': {'key': 'error', 'type': 'ErrorResponseCommon'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationStatus, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.name = kwargs.get('name', None)
        self.start_time = kwargs.get('start_time', None)
        self.end_time = kwargs.get('end_time', None)
        self.status = kwargs.get('status', None)
        self.error = kwargs.get('error', None)


class ProxyResource(msrest.serialization.Model):
    """An azure resource object.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ProxyResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class PrivateEndpointConnection(ProxyResource):
    """A private endpoint connection.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param private_endpoint: Private endpoint which the connection belongs to.
    :type private_endpoint: ~$(python-base-namespace).v2019_10_17.models.PrivateEndpointProperty
    :param private_link_service_connection_state: Connection state of the private endpoint
     connection.
    :type private_link_service_connection_state: ~$(python-base-
     namespace).v2019_10_17.models.PrivateLinkServiceConnectionStateProperty
    :ivar provisioning_state: State of the private endpoint connection.
    :vartype provisioning_state: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'private_endpoint': {'key': 'properties.privateEndpoint', 'type': 'PrivateEndpointProperty'},
        'private_link_service_connection_state': {'key': 'properties.privateLinkServiceConnectionState', 'type': 'PrivateLinkServiceConnectionStateProperty'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateEndpointConnection, self).__init__(**kwargs)
        self.private_endpoint = kwargs.get('private_endpoint', None)
        self.private_link_service_connection_state = kwargs.get('private_link_service_connection_state', None)
        self.provisioning_state = None


class PrivateEndpointConnectionListResult(msrest.serialization.Model):
    """A list of private endpoint connections.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: Array of results.
    :vartype value: list[~$(python-base-namespace).v2019_10_17.models.PrivateEndpointConnection]
    :ivar next_link: Link to retrieve next page of results.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[PrivateEndpointConnection]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateEndpointConnectionListResult, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class PrivateEndpointProperty(msrest.serialization.Model):
    """Private endpoint which the connection belongs to.

    :param id: Resource id of the private endpoint.
    :type id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateEndpointProperty, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)


class PrivateLinkResource(ProxyResource):
    """A private link resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :ivar group_id: The private link resource group id.
    :vartype group_id: str
    :ivar required_members: The private link resource required member names.
    :vartype required_members: list[str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'group_id': {'readonly': True},
        'required_members': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'group_id': {'key': 'properties.groupId', 'type': 'str'},
        'required_members': {'key': 'properties.requiredMembers', 'type': '[str]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkResource, self).__init__(**kwargs)
        self.group_id = None
        self.required_members = None


class PrivateLinkResourceListResult(msrest.serialization.Model):
    """A list of private link resources.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: Array of results.
    :vartype value: list[~$(python-base-namespace).v2019_10_17.models.PrivateLinkResource]
    :ivar next_link: Link to retrieve next page of results.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[PrivateLinkResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkResourceListResult, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class PrivateLinkServiceConnectionStateProperty(msrest.serialization.Model):
    """State of the private endpoint connection.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param status: Required. The private link service connection status.
    :type status: str
    :param description: Required. The private link service connection description.
    :type description: str
    :ivar actions_required: The actions required for private link service connection.
    :vartype actions_required: str
    """

    _validation = {
        'status': {'required': True},
        'description': {'required': True},
        'actions_required': {'readonly': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'actions_required': {'key': 'actionsRequired', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkServiceConnectionStateProperty, self).__init__(**kwargs)
        self.status = kwargs['status']
        self.description = kwargs['description']
        self.actions_required = None


class ScopedResource(ProxyResource):
    """A private link scoped resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param linked_resource_id: The resource id of the scoped Azure monitor resource.
    :type linked_resource_id: str
    :ivar provisioning_state: State of the private endpoint connection.
    :vartype provisioning_state: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'linked_resource_id': {'key': 'properties.linkedResourceId', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ScopedResource, self).__init__(**kwargs)
        self.linked_resource_id = kwargs.get('linked_resource_id', None)
        self.provisioning_state = None


class ScopedResourceListResult(msrest.serialization.Model):
    """A list of scoped resources in a private link scope.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: Array of results.
    :vartype value: list[~$(python-base-namespace).v2019_10_17.models.ScopedResource]
    :ivar next_link: Link to retrieve next page of results.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ScopedResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ScopedResourceListResult, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class TagsResource(msrest.serialization.Model):
    """A container holding only the Tags for a resource, allowing the user to update the tags on a PrivateLinkScope instance.

    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TagsResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
