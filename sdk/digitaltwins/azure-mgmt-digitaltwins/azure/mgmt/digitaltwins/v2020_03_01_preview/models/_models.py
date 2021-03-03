# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class CheckNameRequest(msrest.serialization.Model):
    """The result returned from a database check name availability request.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Resource name.
    :type name: str
    :ivar type: Required. The type of resource, for instance
     Microsoft.DigitalTwins/digitalTwinsInstances. Default value:
     "Microsoft.DigitalTwins/digitalTwinsInstances".
    :vartype type: str
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True, 'constant': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    type = "Microsoft.DigitalTwins/digitalTwinsInstances"

    def __init__(
        self,
        **kwargs
    ):
        super(CheckNameRequest, self).__init__(**kwargs)
        self.name = kwargs['name']


class CheckNameResult(msrest.serialization.Model):
    """The result returned from a check name availability request.

    :param name_available: Specifies a Boolean value that indicates if the name is available.
    :type name_available: bool
    :param name: The name that was checked.
    :type name: str
    :param message: Message indicating an unavailable name due to a conflict, or a description of
     the naming rules that are violated.
    :type message: str
    :param reason: Message providing the reason why the given name is invalid. Possible values
     include: "Invalid", "AlreadyExists".
    :type reason: str or ~azure.mgmt.digitaltwins.models.Reason
    """

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'name': {'key': 'name', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'reason': {'key': 'reason', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CheckNameResult, self).__init__(**kwargs)
        self.name_available = kwargs.get('name_available', None)
        self.name = kwargs.get('name', None)
        self.message = kwargs.get('message', None)
        self.reason = kwargs.get('reason', None)


class DigitalTwinsResource(msrest.serialization.Model):
    """The common properties of a DigitalTwinsInstance.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param location: Required. The resource location.
    :type location: str
    :param tags: A set of tags. The resource tags.
    :type tags: dict[str, str]
    :param sku: This property is reserved for future use, and will be ignored/omitted.
    :type sku: ~azure.mgmt.digitaltwins.models.DigitalTwinsSkuInfo
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True, 'pattern': r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{2,49}[a-zA-Z0-9]$'},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'DigitalTwinsSkuInfo'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DigitalTwinsResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = kwargs['location']
        self.tags = kwargs.get('tags', None)
        self.sku = kwargs.get('sku', None)


class DigitalTwinsDescription(DigitalTwinsResource):
    """The description of the DigitalTwins service.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param location: Required. The resource location.
    :type location: str
    :param tags: A set of tags. The resource tags.
    :type tags: dict[str, str]
    :param sku: This property is reserved for future use, and will be ignored/omitted.
    :type sku: ~azure.mgmt.digitaltwins.models.DigitalTwinsSkuInfo
    :ivar created_time: Time when DigitalTwinsInstance was created.
    :vartype created_time: ~datetime.datetime
    :ivar last_updated_time: Time when DigitalTwinsInstance was created.
    :vartype last_updated_time: ~datetime.datetime
    :ivar provisioning_state: The provisioning state. Possible values include: "Provisioning",
     "Deleting", "Succeeded", "Failed", "Canceled".
    :vartype provisioning_state: str or ~azure.mgmt.digitaltwins.models.ProvisioningState
    :ivar host_name: Api endpoint to work with DigitalTwinsInstance.
    :vartype host_name: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True, 'pattern': r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{2,49}[a-zA-Z0-9]$'},
        'type': {'readonly': True},
        'location': {'required': True},
        'created_time': {'readonly': True},
        'last_updated_time': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'host_name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'DigitalTwinsSkuInfo'},
        'created_time': {'key': 'properties.createdTime', 'type': 'iso-8601'},
        'last_updated_time': {'key': 'properties.lastUpdatedTime', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'host_name': {'key': 'properties.hostName', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DigitalTwinsDescription, self).__init__(**kwargs)
        self.created_time = None
        self.last_updated_time = None
        self.provisioning_state = None
        self.host_name = None


class DigitalTwinsDescriptionListResult(msrest.serialization.Model):
    """A list of DigitalTwins description objects with a next link.

    :param next_link: The link used to get the next page of DigitalTwins description objects.
    :type next_link: str
    :param value: A list of DigitalTwins description objects.
    :type value: list[~azure.mgmt.digitaltwins.models.DigitalTwinsDescription]
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'value': {'key': 'value', 'type': '[DigitalTwinsDescription]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DigitalTwinsDescriptionListResult, self).__init__(**kwargs)
        self.next_link = kwargs.get('next_link', None)
        self.value = kwargs.get('value', None)


class ExternalResource(msrest.serialization.Model):
    """Definition of a Resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: Extension resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True, 'pattern': r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{2,49}[a-zA-Z0-9]$'},
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
        super(ExternalResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class DigitalTwinsEndpointResource(ExternalResource):
    """DigitalTwinsInstance endpoint resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: Extension resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param properties: DigitalTwinsInstance endpoint resource properties.
    :type properties: ~azure.mgmt.digitaltwins.models.DigitalTwinsEndpointResourceProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True, 'pattern': r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{2,49}[a-zA-Z0-9]$'},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'DigitalTwinsEndpointResourceProperties'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DigitalTwinsEndpointResource, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)


class DigitalTwinsEndpointResourceListResult(msrest.serialization.Model):
    """A list of DigitalTwinsInstance Endpoints with a next link.

    :param next_link: The link used to get the next page of DigitalTwinsInstance Endpoints.
    :type next_link: str
    :param value: A list of DigitalTwinsInstance Endpoints.
    :type value: list[~azure.mgmt.digitaltwins.models.DigitalTwinsEndpointResource]
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'value': {'key': 'value', 'type': '[DigitalTwinsEndpointResource]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DigitalTwinsEndpointResourceListResult, self).__init__(**kwargs)
        self.next_link = kwargs.get('next_link', None)
        self.value = kwargs.get('value', None)


class DigitalTwinsEndpointResourceProperties(msrest.serialization.Model):
    """Properties related to Digital Twins Endpoint.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: EventGrid, EventHub, ServiceBus.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param endpoint_type: Required. The type of Digital Twins endpoint.Constant filled by server.
     Possible values include: "EventHub", "EventGrid", "ServiceBus".
    :type endpoint_type: str or ~azure.mgmt.digitaltwins.models.EndpointType
    :ivar provisioning_state: The provisioning state. Possible values include: "Provisioning",
     "Deleting", "Succeeded", "Failed", "Canceled".
    :vartype provisioning_state: str or ~azure.mgmt.digitaltwins.models.EndpointProvisioningState
    :ivar created_time: Time when the Endpoint was added to DigitalTwinsInstance.
    :vartype created_time: ~datetime.datetime
    :param tags: A set of tags. The resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'endpoint_type': {'required': True},
        'provisioning_state': {'readonly': True},
        'created_time': {'readonly': True},
    }

    _attribute_map = {
        'endpoint_type': {'key': 'endpointType', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'created_time': {'key': 'createdTime', 'type': 'iso-8601'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    _subtype_map = {
        'endpoint_type': {'EventGrid': 'EventGrid', 'EventHub': 'EventHub', 'ServiceBus': 'ServiceBus'}
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DigitalTwinsEndpointResourceProperties, self).__init__(**kwargs)
        self.endpoint_type = None  # type: Optional[str]
        self.provisioning_state = None
        self.created_time = None
        self.tags = kwargs.get('tags', None)


class DigitalTwinsPatchDescription(msrest.serialization.Model):
    """The description of the DigitalTwins service.

    :param tags: A set of tags. Instance tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DigitalTwinsPatchDescription, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)


class DigitalTwinsSkuInfo(msrest.serialization.Model):
    """Information about the SKU of the DigitalTwinsInstance.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the SKU. Possible values include: "F1".
    :type name: str or ~azure.mgmt.digitaltwins.models.DigitalTwinsSku
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DigitalTwinsSkuInfo, self).__init__(**kwargs)
        self.name = kwargs['name']


class ErrorDefinition(msrest.serialization.Model):
    """Error definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar code: Service specific error code which serves as the substatus for the HTTP error code.
    :vartype code: str
    :ivar message: Description of the error.
    :vartype message: str
    :ivar details: Internal error details.
    :vartype details: list[~azure.mgmt.digitaltwins.models.ErrorDefinition]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorDefinition]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorDefinition, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.details = None


class ErrorResponse(msrest.serialization.Model):
    """Error response.

    :param error: Error description.
    :type error: ~azure.mgmt.digitaltwins.models.ErrorDefinition
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorDefinition'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class EventGrid(DigitalTwinsEndpointResourceProperties):
    """properties related to eventgrid.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param endpoint_type: Required. The type of Digital Twins endpoint.Constant filled by server.
     Possible values include: "EventHub", "EventGrid", "ServiceBus".
    :type endpoint_type: str or ~azure.mgmt.digitaltwins.models.EndpointType
    :ivar provisioning_state: The provisioning state. Possible values include: "Provisioning",
     "Deleting", "Succeeded", "Failed", "Canceled".
    :vartype provisioning_state: str or ~azure.mgmt.digitaltwins.models.EndpointProvisioningState
    :ivar created_time: Time when the Endpoint was added to DigitalTwinsInstance.
    :vartype created_time: ~datetime.datetime
    :param tags: A set of tags. The resource tags.
    :type tags: dict[str, str]
    :param topic_endpoint: EventGrid Topic Endpoint.
    :type topic_endpoint: str
    :param access_key1: Required. EventGrid secondary accesskey. Will be obfuscated during read.
    :type access_key1: str
    :param access_key2: Required. EventGrid secondary accesskey. Will be obfuscated during read.
    :type access_key2: str
    """

    _validation = {
        'endpoint_type': {'required': True},
        'provisioning_state': {'readonly': True},
        'created_time': {'readonly': True},
        'access_key1': {'required': True},
        'access_key2': {'required': True},
    }

    _attribute_map = {
        'endpoint_type': {'key': 'endpointType', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'created_time': {'key': 'createdTime', 'type': 'iso-8601'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'topic_endpoint': {'key': 'TopicEndpoint', 'type': 'str'},
        'access_key1': {'key': 'accessKey1', 'type': 'str'},
        'access_key2': {'key': 'accessKey2', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(EventGrid, self).__init__(**kwargs)
        self.endpoint_type = 'EventGrid'  # type: str
        self.topic_endpoint = kwargs.get('topic_endpoint', None)
        self.access_key1 = kwargs['access_key1']
        self.access_key2 = kwargs['access_key2']


class EventHub(DigitalTwinsEndpointResourceProperties):
    """properties related to eventhub.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param endpoint_type: Required. The type of Digital Twins endpoint.Constant filled by server.
     Possible values include: "EventHub", "EventGrid", "ServiceBus".
    :type endpoint_type: str or ~azure.mgmt.digitaltwins.models.EndpointType
    :ivar provisioning_state: The provisioning state. Possible values include: "Provisioning",
     "Deleting", "Succeeded", "Failed", "Canceled".
    :vartype provisioning_state: str or ~azure.mgmt.digitaltwins.models.EndpointProvisioningState
    :ivar created_time: Time when the Endpoint was added to DigitalTwinsInstance.
    :vartype created_time: ~datetime.datetime
    :param tags: A set of tags. The resource tags.
    :type tags: dict[str, str]
    :param connection_string_primary_key: Required. PrimaryConnectionString of the endpoint. Will
     be obfuscated during read.
    :type connection_string_primary_key: str
    :param connection_string_secondary_key: Required. SecondaryConnectionString of the endpoint.
     Will be obfuscated during read.
    :type connection_string_secondary_key: str
    """

    _validation = {
        'endpoint_type': {'required': True},
        'provisioning_state': {'readonly': True},
        'created_time': {'readonly': True},
        'connection_string_primary_key': {'required': True},
        'connection_string_secondary_key': {'required': True},
    }

    _attribute_map = {
        'endpoint_type': {'key': 'endpointType', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'created_time': {'key': 'createdTime', 'type': 'iso-8601'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'connection_string_primary_key': {'key': 'connectionString-PrimaryKey', 'type': 'str'},
        'connection_string_secondary_key': {'key': 'connectionString-SecondaryKey', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(EventHub, self).__init__(**kwargs)
        self.endpoint_type = 'EventHub'  # type: str
        self.connection_string_primary_key = kwargs['connection_string_primary_key']
        self.connection_string_secondary_key = kwargs['connection_string_secondary_key']


class Operation(msrest.serialization.Model):
    """DigitalTwins service REST API operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar name: Operation name: {provider}/{resource}/{read | write | action | delete}.
    :vartype name: str
    :param display: Operation properties display.
    :type display: ~azure.mgmt.digitaltwins.models.OperationDisplay
    """

    _validation = {
        'name': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Operation, self).__init__(**kwargs)
        self.name = None
        self.display = kwargs.get('display', None)


class OperationDisplay(msrest.serialization.Model):
    """The object that represents the operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar provider: Service provider: Microsoft DigitalTwins.
    :vartype provider: str
    :ivar resource: Resource Type: DigitalTwinsInstances.
    :vartype resource: str
    :ivar operation: Name of the operation.
    :vartype operation: str
    :ivar description: Friendly description for the operation,.
    :vartype description: str
    """

    _validation = {
        'provider': {'readonly': True},
        'resource': {'readonly': True},
        'operation': {'readonly': True},
        'description': {'readonly': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = None
        self.resource = None
        self.operation = None
        self.description = None


class OperationListResult(msrest.serialization.Model):
    """A list of DigitalTwins service operations. It contains a list of operations and a URL link to get the next set of results.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param next_link: The link used to get the next page of DigitalTwins description objects.
    :type next_link: str
    :ivar value: A list of DigitalTwins operations supported by the Microsoft.DigitalTwins resource
     provider.
    :vartype value: list[~azure.mgmt.digitaltwins.models.Operation]
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'value': {'key': 'value', 'type': '[Operation]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationListResult, self).__init__(**kwargs)
        self.next_link = kwargs.get('next_link', None)
        self.value = None


class ServiceBus(DigitalTwinsEndpointResourceProperties):
    """properties related to servicebus.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param endpoint_type: Required. The type of Digital Twins endpoint.Constant filled by server.
     Possible values include: "EventHub", "EventGrid", "ServiceBus".
    :type endpoint_type: str or ~azure.mgmt.digitaltwins.models.EndpointType
    :ivar provisioning_state: The provisioning state. Possible values include: "Provisioning",
     "Deleting", "Succeeded", "Failed", "Canceled".
    :vartype provisioning_state: str or ~azure.mgmt.digitaltwins.models.EndpointProvisioningState
    :ivar created_time: Time when the Endpoint was added to DigitalTwinsInstance.
    :vartype created_time: ~datetime.datetime
    :param tags: A set of tags. The resource tags.
    :type tags: dict[str, str]
    :param primary_connection_string: Required. PrimaryConnectionString of the endpoint. Will be
     obfuscated during read.
    :type primary_connection_string: str
    :param secondary_connection_string: Required. SecondaryConnectionString of the endpoint. Will
     be obfuscated during read.
    :type secondary_connection_string: str
    """

    _validation = {
        'endpoint_type': {'required': True},
        'provisioning_state': {'readonly': True},
        'created_time': {'readonly': True},
        'primary_connection_string': {'required': True},
        'secondary_connection_string': {'required': True},
    }

    _attribute_map = {
        'endpoint_type': {'key': 'endpointType', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'created_time': {'key': 'createdTime', 'type': 'iso-8601'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'primary_connection_string': {'key': 'primaryConnectionString', 'type': 'str'},
        'secondary_connection_string': {'key': 'secondaryConnectionString', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ServiceBus, self).__init__(**kwargs)
        self.endpoint_type = 'ServiceBus'  # type: str
        self.primary_connection_string = kwargs['primary_connection_string']
        self.secondary_connection_string = kwargs['secondary_connection_string']
