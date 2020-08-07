# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import datetime
from typing import Dict, List, Optional, Union

import msrest.serialization

from ._event_hub_management_client_enums import *


class CheckNameAvailabilityParameter(msrest.serialization.Model):
    """Parameter supplied to check Namespace name availability operation.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Name to check the namespace name availability.
    :type name: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: str,
        **kwargs
    ):
        super(CheckNameAvailabilityParameter, self).__init__(**kwargs)
        self.name = name


class CheckNameAvailabilityResult(msrest.serialization.Model):
    """The Result of the CheckNameAvailability operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param name_available: Value indicating Namespace is availability, true if the Namespace is
     available; otherwise, false.
    :type name_available: bool
    :param reason: The reason for unavailability of a Namespace. Possible values include: "None",
     "InvalidName", "SubscriptionIsDisabled", "NameInUse", "NameInLockdown",
     "TooManyNamespaceInCurrentSubscription".
    :type reason: str or ~azure.mgmt.eventhub.v2015_08_01.models.UnavailableReason
    :ivar message: The detailed info regarding the reason associated with the Namespace.
    :vartype message: str
    """

    _validation = {
        'message': {'readonly': True},
    }

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name_available: Optional[bool] = None,
        reason: Optional[Union[str, "UnavailableReason"]] = None,
        **kwargs
    ):
        super(CheckNameAvailabilityResult, self).__init__(**kwargs)
        self.name_available = name_available
        self.reason = reason
        self.message = None


class ConsumerGroupCreateOrUpdateParameters(msrest.serialization.Model):
    """Parameters supplied to the Create Or Update Consumer Group operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. Location of the resource.
    :type location: str
    :param type: ARM type of the Namespace.
    :type type: str
    :param name: Name of the consumer group.
    :type name: str
    :ivar created_at: Exact time the message was created.
    :vartype created_at: ~datetime.datetime
    :ivar event_hub_path: The path of the Event Hub.
    :vartype event_hub_path: str
    :ivar updated_at: The exact time the message was updated.
    :vartype updated_at: ~datetime.datetime
    :param user_metadata: The user metadata.
    :type user_metadata: str
    """

    _validation = {
        'location': {'required': True},
        'created_at': {'readonly': True},
        'event_hub_path': {'readonly': True},
        'updated_at': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'event_hub_path': {'key': 'properties.eventHubPath', 'type': 'str'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'user_metadata': {'key': 'properties.userMetadata', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        location: str,
        type: Optional[str] = None,
        name: Optional[str] = None,
        user_metadata: Optional[str] = None,
        **kwargs
    ):
        super(ConsumerGroupCreateOrUpdateParameters, self).__init__(**kwargs)
        self.location = location
        self.type = type
        self.name = name
        self.created_at = None
        self.event_hub_path = None
        self.updated_at = None
        self.user_metadata = user_metadata


class ConsumerGroupListResult(msrest.serialization.Model):
    """The result to the List Consumer Group operation.

    :param value: Result of the List Consumer Group operation.
    :type value: list[~azure.mgmt.eventhub.v2015_08_01.models.ConsumerGroupResource]
    :param next_link: Link to the next set of results. Not empty if Value contains incomplete list
     of Consumer Group.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ConsumerGroupResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["ConsumerGroupResource"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(ConsumerGroupListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class Resource(msrest.serialization.Model):
    """The Resource definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :param location: Resource location.
    :type location: str
    :ivar type: Resource type.
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
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        location: Optional[str] = None,
        **kwargs
    ):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.location = location
        self.type = None


class ConsumerGroupResource(Resource):
    """Single item in List or Get Consumer group operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :param location: Resource location.
    :type location: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar created_at: Exact time the message was created.
    :vartype created_at: ~datetime.datetime
    :ivar event_hub_path: The path of the Event Hub.
    :vartype event_hub_path: str
    :ivar updated_at: The exact time the message was updated.
    :vartype updated_at: ~datetime.datetime
    :param user_metadata: The user metadata.
    :type user_metadata: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_at': {'readonly': True},
        'event_hub_path': {'readonly': True},
        'updated_at': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'event_hub_path': {'key': 'properties.eventHubPath', 'type': 'str'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'user_metadata': {'key': 'properties.userMetadata', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        location: Optional[str] = None,
        user_metadata: Optional[str] = None,
        **kwargs
    ):
        super(ConsumerGroupResource, self).__init__(location=location, **kwargs)
        self.created_at = None
        self.event_hub_path = None
        self.updated_at = None
        self.user_metadata = user_metadata


class EventHubCreateOrUpdateParameters(msrest.serialization.Model):
    """Parameters supplied to the Create Or Update Event Hub operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. Location of the resource.
    :type location: str
    :param type: ARM type of the Namespace.
    :type type: str
    :param name: Name of the Event Hub.
    :type name: str
    :ivar created_at: Exact time the Event Hub was created.
    :vartype created_at: ~datetime.datetime
    :param message_retention_in_days: Number of days to retain the events for this Event Hub.
    :type message_retention_in_days: long
    :param partition_count: Number of partitions created for the Event Hub.
    :type partition_count: long
    :ivar partition_ids: Current number of shards on the Event Hub.
    :vartype partition_ids: list[str]
    :param status: Enumerates the possible values for the status of the Event Hub. Possible values
     include: "Active", "Disabled", "Restoring", "SendDisabled", "ReceiveDisabled", "Creating",
     "Deleting", "Renaming", "Unknown".
    :type status: str or ~azure.mgmt.eventhub.v2015_08_01.models.EntityStatus
    :ivar updated_at: The exact time the message was updated.
    :vartype updated_at: ~datetime.datetime
    """

    _validation = {
        'location': {'required': True},
        'created_at': {'readonly': True},
        'partition_ids': {'readonly': True},
        'updated_at': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'message_retention_in_days': {'key': 'properties.messageRetentionInDays', 'type': 'long'},
        'partition_count': {'key': 'properties.partitionCount', 'type': 'long'},
        'partition_ids': {'key': 'properties.partitionIds', 'type': '[str]'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        *,
        location: str,
        type: Optional[str] = None,
        name: Optional[str] = None,
        message_retention_in_days: Optional[int] = None,
        partition_count: Optional[int] = None,
        status: Optional[Union[str, "EntityStatus"]] = None,
        **kwargs
    ):
        super(EventHubCreateOrUpdateParameters, self).__init__(**kwargs)
        self.location = location
        self.type = type
        self.name = name
        self.created_at = None
        self.message_retention_in_days = message_retention_in_days
        self.partition_count = partition_count
        self.partition_ids = None
        self.status = status
        self.updated_at = None


class EventHubListResult(msrest.serialization.Model):
    """The result of the List EventHubs operation.

    :param value: Result of the List EventHubs operation.
    :type value: list[~azure.mgmt.eventhub.v2015_08_01.models.EventHubResource]
    :param next_link: Link to the next set of results. Not empty if Value contains incomplete list
     of EventHubs.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[EventHubResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["EventHubResource"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(EventHubListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class EventHubResource(Resource):
    """Single item in List or Get Event Hub operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :param location: Resource location.
    :type location: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar created_at: Exact time the Event Hub was created.
    :vartype created_at: ~datetime.datetime
    :param message_retention_in_days: Number of days to retain the events for this Event Hub.
    :type message_retention_in_days: long
    :param partition_count: Number of partitions created for the Event Hub.
    :type partition_count: long
    :ivar partition_ids: Current number of shards on the Event Hub.
    :vartype partition_ids: list[str]
    :param status: Enumerates the possible values for the status of the Event Hub. Possible values
     include: "Active", "Disabled", "Restoring", "SendDisabled", "ReceiveDisabled", "Creating",
     "Deleting", "Renaming", "Unknown".
    :type status: str or ~azure.mgmt.eventhub.v2015_08_01.models.EntityStatus
    :ivar updated_at: The exact time the message was updated.
    :vartype updated_at: ~datetime.datetime
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_at': {'readonly': True},
        'partition_ids': {'readonly': True},
        'updated_at': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'message_retention_in_days': {'key': 'properties.messageRetentionInDays', 'type': 'long'},
        'partition_count': {'key': 'properties.partitionCount', 'type': 'long'},
        'partition_ids': {'key': 'properties.partitionIds', 'type': '[str]'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        *,
        location: Optional[str] = None,
        message_retention_in_days: Optional[int] = None,
        partition_count: Optional[int] = None,
        status: Optional[Union[str, "EntityStatus"]] = None,
        **kwargs
    ):
        super(EventHubResource, self).__init__(location=location, **kwargs)
        self.created_at = None
        self.message_retention_in_days = message_retention_in_days
        self.partition_count = partition_count
        self.partition_ids = None
        self.status = status
        self.updated_at = None


class NamespaceCreateOrUpdateParameters(msrest.serialization.Model):
    """Parameters supplied to the Create Or Update Namespace operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. Namespace location.
    :type location: str
    :param sku: SKU parameters supplied to the create Namespace operation.
    :type sku: ~azure.mgmt.eventhub.v2015_08_01.models.Sku
    :param tags: A set of tags. Namespace tags.
    :type tags: dict[str, str]
    :param status: State of the Namespace. Possible values include: "Unknown", "Creating",
     "Created", "Activating", "Enabling", "Active", "Disabling", "Disabled", "SoftDeleting",
     "SoftDeleted", "Removing", "Removed", "Failed".
    :type status: str or ~azure.mgmt.eventhub.v2015_08_01.models.NamespaceState
    :param provisioning_state: Provisioning state of the Namespace.
    :type provisioning_state: str
    :param created_at: The time the Namespace was created.
    :type created_at: ~datetime.datetime
    :param updated_at: The time the Namespace was updated.
    :type updated_at: ~datetime.datetime
    :param service_bus_endpoint: Endpoint you can use to perform Service Bus operations.
    :type service_bus_endpoint: str
    :ivar metric_id: Identifier for Azure Insights metrics.
    :vartype metric_id: str
    :param enabled: Specifies whether this instance is enabled.
    :type enabled: bool
    """

    _validation = {
        'location': {'required': True},
        'metric_id': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'service_bus_endpoint': {'key': 'properties.serviceBusEndpoint', 'type': 'str'},
        'metric_id': {'key': 'properties.metricId', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        location: str,
        sku: Optional["Sku"] = None,
        tags: Optional[Dict[str, str]] = None,
        status: Optional[Union[str, "NamespaceState"]] = None,
        provisioning_state: Optional[str] = None,
        created_at: Optional[datetime.datetime] = None,
        updated_at: Optional[datetime.datetime] = None,
        service_bus_endpoint: Optional[str] = None,
        enabled: Optional[bool] = None,
        **kwargs
    ):
        super(NamespaceCreateOrUpdateParameters, self).__init__(**kwargs)
        self.location = location
        self.sku = sku
        self.tags = tags
        self.status = status
        self.provisioning_state = provisioning_state
        self.created_at = created_at
        self.updated_at = updated_at
        self.service_bus_endpoint = service_bus_endpoint
        self.metric_id = None
        self.enabled = enabled


class NamespaceListResult(msrest.serialization.Model):
    """The response of the List Namespace operation.

    :param value: Result of the List Namespace operation.
    :type value: list[~azure.mgmt.eventhub.v2015_08_01.models.NamespaceResource]
    :param next_link: Link to the next set of results. Not empty if Value contains incomplete list
     of namespaces.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[NamespaceResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["NamespaceResource"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(NamespaceListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class TrackedResource(Resource):
    """Definition of Resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :param location: Resource location.
    :type location: str
    :ivar type: Resource type.
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        location: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(TrackedResource, self).__init__(location=location, **kwargs)
        self.tags = tags


class NamespaceResource(TrackedResource):
    """Single Namespace item in List or Get Operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :param location: Resource location.
    :type location: str
    :ivar type: Resource type.
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param sku: SKU parameters supplied to the create Namespace operation.
    :type sku: ~azure.mgmt.eventhub.v2015_08_01.models.Sku
    :param status: State of the Namespace. Possible values include: "Unknown", "Creating",
     "Created", "Activating", "Enabling", "Active", "Disabling", "Disabled", "SoftDeleting",
     "SoftDeleted", "Removing", "Removed", "Failed".
    :type status: str or ~azure.mgmt.eventhub.v2015_08_01.models.NamespaceState
    :param provisioning_state: Provisioning state of the Namespace.
    :type provisioning_state: str
    :param created_at: The time the Namespace was created.
    :type created_at: ~datetime.datetime
    :param updated_at: The time the Namespace was updated.
    :type updated_at: ~datetime.datetime
    :param service_bus_endpoint: Endpoint you can use to perform Service Bus operations.
    :type service_bus_endpoint: str
    :ivar metric_id: Identifier for Azure Insights metrics.
    :vartype metric_id: str
    :param enabled: Specifies whether this instance is enabled.
    :type enabled: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'metric_id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'service_bus_endpoint': {'key': 'properties.serviceBusEndpoint', 'type': 'str'},
        'metric_id': {'key': 'properties.metricId', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        location: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        sku: Optional["Sku"] = None,
        status: Optional[Union[str, "NamespaceState"]] = None,
        provisioning_state: Optional[str] = None,
        created_at: Optional[datetime.datetime] = None,
        updated_at: Optional[datetime.datetime] = None,
        service_bus_endpoint: Optional[str] = None,
        enabled: Optional[bool] = None,
        **kwargs
    ):
        super(NamespaceResource, self).__init__(location=location, tags=tags, **kwargs)
        self.sku = sku
        self.status = status
        self.provisioning_state = provisioning_state
        self.created_at = created_at
        self.updated_at = updated_at
        self.service_bus_endpoint = service_bus_endpoint
        self.metric_id = None
        self.enabled = enabled


class NamespaceUpdateParameter(msrest.serialization.Model):
    """Parameters supplied to the Patch/update Namespace operation.

    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param sku: The sku of the created Namespace.
    :type sku: ~azure.mgmt.eventhub.v2015_08_01.models.Sku
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
    }

    def __init__(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        sku: Optional["Sku"] = None,
        **kwargs
    ):
        super(NamespaceUpdateParameter, self).__init__(**kwargs)
        self.tags = tags
        self.sku = sku


class Operation(msrest.serialization.Model):
    """A Event Hub REST API operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar name: Operation name: {provider}/{resource}/{operation}.
    :vartype name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.eventhub.v2015_08_01.models.OperationDisplay
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
        *,
        display: Optional["OperationDisplay"] = None,
        **kwargs
    ):
        super(Operation, self).__init__(**kwargs)
        self.name = None
        self.display = display


class OperationDisplay(msrest.serialization.Model):
    """The object that represents the operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar provider: Service provider: Microsoft.EventHub.
    :vartype provider: str
    :ivar resource: Resource on which the operation is performed: Invoice, etc.
    :vartype resource: str
    :ivar operation: Operation type: Read, write, delete, etc.
    :vartype operation: str
    """

    _validation = {
        'provider': {'readonly': True},
        'resource': {'readonly': True},
        'operation': {'readonly': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = None
        self.resource = None
        self.operation = None


class OperationListResult(msrest.serialization.Model):
    """Result of the request to list Event Hub operations. It contains a list of operations and a URL link to get the next set of results.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: List of Event Hub operations supported by the Microsoft.EventHub resource
     provider.
    :vartype value: list[~azure.mgmt.eventhub.v2015_08_01.models.Operation]
    :ivar next_link: URL to get the next set of operation list results if there are any.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationListResult, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class RegenerateKeysParameters(msrest.serialization.Model):
    """Parameters supplied to the Regenerate Authorization Rule keys operation.

    :param policykey: Key that needs to be regenerated. Possible values include: "PrimaryKey",
     "SecondaryKey".
    :type policykey: str or ~azure.mgmt.eventhub.v2015_08_01.models.Policykey
    """

    _attribute_map = {
        'policykey': {'key': 'policykey', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        policykey: Optional[Union[str, "Policykey"]] = None,
        **kwargs
    ):
        super(RegenerateKeysParameters, self).__init__(**kwargs)
        self.policykey = policykey


class ResourceListKeys(msrest.serialization.Model):
    """Namespace/EventHub Connection String.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar primary_connection_string: Primary connection string of the created Namespace
     AuthorizationRule.
    :vartype primary_connection_string: str
    :ivar secondary_connection_string: Secondary connection string of the created Namespace
     AuthorizationRule.
    :vartype secondary_connection_string: str
    :ivar primary_key: A base64-encoded 256-bit primary key for signing and validating the SAS
     token.
    :vartype primary_key: str
    :ivar secondary_key: A base64-encoded 256-bit primary key for signing and validating the SAS
     token.
    :vartype secondary_key: str
    :ivar key_name: A string that describes the AuthorizationRule.
    :vartype key_name: str
    """

    _validation = {
        'primary_connection_string': {'readonly': True},
        'secondary_connection_string': {'readonly': True},
        'primary_key': {'readonly': True},
        'secondary_key': {'readonly': True},
        'key_name': {'readonly': True},
    }

    _attribute_map = {
        'primary_connection_string': {'key': 'primaryConnectionString', 'type': 'str'},
        'secondary_connection_string': {'key': 'secondaryConnectionString', 'type': 'str'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'key_name': {'key': 'keyName', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ResourceListKeys, self).__init__(**kwargs)
        self.primary_connection_string = None
        self.secondary_connection_string = None
        self.primary_key = None
        self.secondary_key = None
        self.key_name = None


class SharedAccessAuthorizationRuleCreateOrUpdateParameters(msrest.serialization.Model):
    """Parameters supplied to the Create Or Update Authorization Rules operation.

    :param location: Data center location.
    :type location: str
    :param name: Name of the AuthorizationRule.
    :type name: str
    :param rights: The rights associated with the rule.
    :type rights: list[str or ~azure.mgmt.eventhub.v2015_08_01.models.AccessRights]
    """

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'rights': {'key': 'properties.rights', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        location: Optional[str] = None,
        name: Optional[str] = None,
        rights: Optional[List[Union[str, "AccessRights"]]] = None,
        **kwargs
    ):
        super(SharedAccessAuthorizationRuleCreateOrUpdateParameters, self).__init__(**kwargs)
        self.location = location
        self.name = name
        self.rights = rights


class SharedAccessAuthorizationRuleListResult(msrest.serialization.Model):
    """The response from the List Namespace operation.

    :param value: Result of the List Authorization Rules operation.
    :type value:
     list[~azure.mgmt.eventhub.v2015_08_01.models.SharedAccessAuthorizationRuleResource]
    :param next_link: Link to the next set of results. Not empty if Value contains an incomplete
     list of Authorization Rules.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[SharedAccessAuthorizationRuleResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["SharedAccessAuthorizationRuleResource"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(SharedAccessAuthorizationRuleListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class SharedAccessAuthorizationRuleResource(Resource):
    """Single item in a List or Get AuthorizationRule operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :param location: Resource location.
    :type location: str
    :ivar type: Resource type.
    :vartype type: str
    :param rights: The rights associated with the rule.
    :type rights: list[str or ~azure.mgmt.eventhub.v2015_08_01.models.AccessRights]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'rights': {'key': 'properties.rights', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        location: Optional[str] = None,
        rights: Optional[List[Union[str, "AccessRights"]]] = None,
        **kwargs
    ):
        super(SharedAccessAuthorizationRuleResource, self).__init__(location=location, **kwargs)
        self.rights = rights


class Sku(msrest.serialization.Model):
    """SKU parameters supplied to the create Namespace operation.

    All required parameters must be populated in order to send to Azure.

    :param name: Name of this SKU. Possible values include: "Basic", "Standard".
    :type name: str or ~azure.mgmt.eventhub.v2015_08_01.models.SkuName
    :param tier: Required. The billing tier of this particular SKU. Possible values include:
     "Basic", "Standard", "Premium".
    :type tier: str or ~azure.mgmt.eventhub.v2015_08_01.models.SkuTier
    :param capacity: The Event Hubs throughput units.
    :type capacity: int
    """

    _validation = {
        'tier': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        tier: Union[str, "SkuTier"],
        name: Optional[Union[str, "SkuName"]] = None,
        capacity: Optional[int] = None,
        **kwargs
    ):
        super(Sku, self).__init__(**kwargs)
        self.name = name
        self.tier = tier
        self.capacity = capacity
