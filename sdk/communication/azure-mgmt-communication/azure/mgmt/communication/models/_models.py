# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class CommunicationServiceKeys(msrest.serialization.Model):
    """A class representing the access keys of a CommunicationService.

    :param primary_key: The primary access key.
    :type primary_key: str
    :param secondary_key: The secondary access key.
    :type secondary_key: str
    :param primary_connection_string: CommunicationService connection string constructed via the
     primaryKey.
    :type primary_connection_string: str
    :param secondary_connection_string: CommunicationService connection string constructed via the
     secondaryKey.
    :type secondary_connection_string: str
    """

    _attribute_map = {
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'primary_connection_string': {'key': 'primaryConnectionString', 'type': 'str'},
        'secondary_connection_string': {'key': 'secondaryConnectionString', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CommunicationServiceKeys, self).__init__(**kwargs)
        self.primary_key = kwargs.get('primary_key', None)
        self.secondary_key = kwargs.get('secondary_key', None)
        self.primary_connection_string = kwargs.get('primary_connection_string', None)
        self.secondary_connection_string = kwargs.get('secondary_connection_string', None)


class TaggedResource(msrest.serialization.Model):
    """An ARM resource with that can accept tags.

    :param tags: A set of tags. Tags of the service which is a list of key value pairs that
     describe the resource.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TaggedResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)


class LocationResource(msrest.serialization.Model):
    """An ARM resource with its own location (not a global or an inherited location).

    :param location: The Azure location where the CommunicationService is running.
    :type location: str
    """

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LocationResource, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)


class Resource(msrest.serialization.Model):
    """The core properties of ARM resources.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource ID for the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the service - e.g. "Microsoft.Communication/CommunicationServices".
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
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class CommunicationServiceResource(Resource, LocationResource, TaggedResource):
    """A class representing a CommunicationService resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param tags: A set of tags. Tags of the service which is a list of key value pairs that
     describe the resource.
    :type tags: dict[str, str]
    :param location: The Azure location where the CommunicationService is running.
    :type location: str
    :ivar id: Fully qualified resource ID for the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the service - e.g. "Microsoft.Communication/CommunicationServices".
    :vartype type: str
    :ivar provisioning_state: Provisioning state of the resource. Possible values include:
     "Unknown", "Succeeded", "Failed", "Canceled", "Running", "Creating", "Updating", "Deleting",
     "Moving".
    :vartype provisioning_state: str or
     ~communication_service_management_client.models.ProvisioningState
    :ivar host_name: FQDN of the CommunicationService instance.
    :vartype host_name: str
    :param data_location: The location where the communication service stores its data at rest.
    :type data_location: str
    :ivar notification_hub_id: Resource ID of an Azure Notification Hub linked to this resource.
    :vartype notification_hub_id: str
    :ivar version: Version of the CommunicationService resource. Probably you need the same or
     higher version of client SDKs.
    :vartype version: str
    :ivar immutable_resource_id: The immutable resource Id of the communication service.
    :vartype immutable_resource_id: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'host_name': {'readonly': True},
        'notification_hub_id': {'readonly': True},
        'version': {'readonly': True},
        'immutable_resource_id': {'readonly': True},
    }

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'host_name': {'key': 'properties.hostName', 'type': 'str'},
        'data_location': {'key': 'properties.dataLocation', 'type': 'str'},
        'notification_hub_id': {'key': 'properties.notificationHubId', 'type': 'str'},
        'version': {'key': 'properties.version', 'type': 'str'},
        'immutable_resource_id': {'key': 'properties.immutableResourceId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CommunicationServiceResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.location = kwargs.get('location', None)
        self.provisioning_state = None
        self.host_name = None
        self.data_location = kwargs.get('data_location', None)
        self.notification_hub_id = None
        self.version = None
        self.immutable_resource_id = None
        self.tags = kwargs.get('tags', None)
        self.id = None
        self.name = None
        self.type = None
        self.provisioning_state = None
        self.host_name = None
        self.data_location = kwargs.get('data_location', None)
        self.notification_hub_id = None
        self.version = None
        self.immutable_resource_id = None
        self.location = kwargs.get('location', None)
        self.id = None
        self.name = None
        self.type = None
        self.provisioning_state = None
        self.host_name = None
        self.data_location = kwargs.get('data_location', None)
        self.notification_hub_id = None
        self.version = None
        self.immutable_resource_id = None


class CommunicationServiceResourceList(msrest.serialization.Model):
    """Object that includes an array of CommunicationServices and a possible link for next set.

    :param value: List of CommunicationService.
    :type value: list[~communication_service_management_client.models.CommunicationServiceResource]
    :param next_link: The URL the client should use to fetch the next page (per server side
     paging).
     It's null for now, added for future use.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[CommunicationServiceResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CommunicationServiceResourceList, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


class Dimension(msrest.serialization.Model):
    """Specifications of the Dimension of metrics.

    :param name: The public facing name of the dimension.
    :type name: str
    :param display_name: Localized friendly display name of the dimension.
    :type display_name: str
    :param internal_name: Name of the dimension as it appears in MDM.
    :type internal_name: str
    :param to_be_exported_for_shoebox: A Boolean flag indicating whether this dimension should be
     included for the shoebox export scenario.
    :type to_be_exported_for_shoebox: bool
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'internal_name': {'key': 'internalName', 'type': 'str'},
        'to_be_exported_for_shoebox': {'key': 'toBeExportedForShoebox', 'type': 'bool'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Dimension, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display_name = kwargs.get('display_name', None)
        self.internal_name = kwargs.get('internal_name', None)
        self.to_be_exported_for_shoebox = kwargs.get('to_be_exported_for_shoebox', None)


class ErrorResponse(msrest.serialization.Model):
    """Error response indicating why the requested operation could not be performed.

    :param error: The error.
    :type error: ~communication_service_management_client.models.ErrorResponseError
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponseError'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class ErrorResponseError(msrest.serialization.Model):
    """The error.

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
        super(ErrorResponseError, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)


class LinkedNotificationHub(msrest.serialization.Model):
    """A notification hub that has been linked to the communication service.

    :param resource_id: The resource ID of the notification hub.
    :type resource_id: str
    """

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LinkedNotificationHub, self).__init__(**kwargs)
        self.resource_id = kwargs.get('resource_id', None)


class LinkNotificationHubParameters(msrest.serialization.Model):
    """Description of an Azure Notification Hub to link to the communication service.

    All required parameters must be populated in order to send to Azure.

    :param resource_id: Required. The resource ID of the notification hub.
    :type resource_id: str
    :param connection_string: Required. Connection string for the notification hub.
    :type connection_string: str
    """

    _validation = {
        'resource_id': {'required': True},
        'connection_string': {'required': True},
    }

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'connection_string': {'key': 'connectionString', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LinkNotificationHubParameters, self).__init__(**kwargs)
        self.resource_id = kwargs['resource_id']
        self.connection_string = kwargs['connection_string']


class MetricSpecification(msrest.serialization.Model):
    """Specifications of the Metrics for Azure Monitoring.

    :param name: Name of the metric.
    :type name: str
    :param display_name: Localized friendly display name of the metric.
    :type display_name: str
    :param display_description: Localized friendly description of the metric.
    :type display_description: str
    :param unit: The unit that makes sense for the metric.
    :type unit: str
    :param aggregation_type: The method for aggregating the metric. Possible values include:
     "Average", "Minimum", "Maximum", "Total", "Count".
    :type aggregation_type: str or ~communication_service_management_client.models.AggregationType
    :param fill_gap_with_zero: Optional. If set to true, then zero will be returned for time
     duration where no metric is emitted/published.
     Ex. a metric that returns the number of times a particular error code was emitted. The error
     code may not appear
     often, instead of the RP publishing 0, Shoebox can auto fill in 0s for time periods where
     nothing was emitted.
    :type fill_gap_with_zero: str
    :param category: The name of the metric category that the metric belongs to. A metric can only
     belong to a single category.
    :type category: str
    :param dimensions: The dimensions of the metrics.
    :type dimensions: list[~communication_service_management_client.models.Dimension]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'display_description': {'key': 'displayDescription', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
        'aggregation_type': {'key': 'aggregationType', 'type': 'str'},
        'fill_gap_with_zero': {'key': 'fillGapWithZero', 'type': 'str'},
        'category': {'key': 'category', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[Dimension]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricSpecification, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display_name = kwargs.get('display_name', None)
        self.display_description = kwargs.get('display_description', None)
        self.unit = kwargs.get('unit', None)
        self.aggregation_type = kwargs.get('aggregation_type', None)
        self.fill_gap_with_zero = kwargs.get('fill_gap_with_zero', None)
        self.category = kwargs.get('category', None)
        self.dimensions = kwargs.get('dimensions', None)


class Operation(msrest.serialization.Model):
    """REST API operation supported by CommunicationService resource provider.

    :param name: Name of the operation with format: {provider}/{resource}/{operation}.
    :type name: str
    :param display: The object that describes the operation.
    :type display: ~communication_service_management_client.models.OperationDisplay
    :param origin: Optional. The intended executor of the operation; governs the display of the
     operation in the RBAC UX and the audit logs UX.
    :type origin: str
    :param properties: Extra properties for the operation.
    :type properties: ~communication_service_management_client.models.OperationProperties
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'OperationProperties'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Operation, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display = kwargs.get('display', None)
        self.origin = kwargs.get('origin', None)
        self.properties = kwargs.get('properties', None)


class OperationDisplay(msrest.serialization.Model):
    """The object that describes a operation.

    :param provider: Friendly name of the resource provider.
    :type provider: str
    :param resource: Resource type on which the operation is performed.
    :type resource: str
    :param operation: The localized friendly name for the operation.
    :type operation: str
    :param description: The localized friendly description for the operation.
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
        **kwargs
    ):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
        self.operation = kwargs.get('operation', None)
        self.description = kwargs.get('description', None)


class OperationList(msrest.serialization.Model):
    """Result of the request to list REST API operations. It contains a list of operations.

    :param value: List of operations supported by the resource provider.
    :type value: list[~communication_service_management_client.models.Operation]
    :param next_link: The URL the client should use to fetch the next page (per server side
     paging).
     It's null for now, added for future use.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationList, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


class OperationProperties(msrest.serialization.Model):
    """Extra Operation properties.

    :param service_specification: The service specifications.
    :type service_specification:
     ~communication_service_management_client.models.ServiceSpecification
    """

    _attribute_map = {
        'service_specification': {'key': 'serviceSpecification', 'type': 'ServiceSpecification'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationProperties, self).__init__(**kwargs)
        self.service_specification = kwargs.get('service_specification', None)


class OperationStatus(msrest.serialization.Model):
    """The current status of an async operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The operation Id.
    :vartype id: str
    :ivar status: Provisioning state of the resource. Possible values include: "Succeeded",
     "Failed", "Canceled", "Creating", "Deleting", "Moving".
    :vartype status: str or ~communication_service_management_client.models.Status
    :ivar start_time: The start time of the operation.
    :vartype start_time: ~datetime.datetime
    :ivar end_time: The end time of the operation.
    :vartype end_time: ~datetime.datetime
    :ivar percent_complete: Percent of the operation that is complete.
    :vartype percent_complete: float
    :param error: The error.
    :type error: ~communication_service_management_client.models.ErrorResponseError
    """

    _validation = {
        'id': {'readonly': True},
        'status': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
        'percent_complete': {'readonly': True, 'maximum': 100, 'minimum': 0},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'percent_complete': {'key': 'percentComplete', 'type': 'float'},
        'error': {'key': 'error.error', 'type': 'ErrorResponseError'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationStatus, self).__init__(**kwargs)
        self.id = None
        self.status = None
        self.start_time = None
        self.end_time = None
        self.percent_complete = None
        self.error = kwargs.get('error', None)


class RegenerateKeyParameters(msrest.serialization.Model):
    """Parameters describes the request to regenerate access keys.

    :param key_type: The keyType to regenerate. Must be either 'primary' or 'secondary'(case-
     insensitive). Possible values include: "Primary", "Secondary".
    :type key_type: str or ~communication_service_management_client.models.KeyType
    """

    _attribute_map = {
        'key_type': {'key': 'keyType', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RegenerateKeyParameters, self).__init__(**kwargs)
        self.key_type = kwargs.get('key_type', None)


class ServiceSpecification(msrest.serialization.Model):
    """An object that describes a specification.

    :param metric_specifications: Specifications of the Metrics for Azure Monitoring.
    :type metric_specifications:
     list[~communication_service_management_client.models.MetricSpecification]
    """

    _attribute_map = {
        'metric_specifications': {'key': 'metricSpecifications', 'type': '[MetricSpecification]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ServiceSpecification, self).__init__(**kwargs)
        self.metric_specifications = kwargs.get('metric_specifications', None)
