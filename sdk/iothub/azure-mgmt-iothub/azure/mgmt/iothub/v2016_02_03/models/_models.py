# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model
from msrest.exceptions import HttpOperationError


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class CloudToDeviceProperties(Model):
    """The IoT hub cloud-to-device messaging properties.

    :param max_delivery_count: The max delivery count for cloud-to-device
     messages in the device queue. See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messaging#cloud-to-device-messages.
    :type max_delivery_count: int
    :param default_ttl_as_iso8601: The default time to live for
     cloud-to-device messages in the device queue. See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messaging#cloud-to-device-messages.
    :type default_ttl_as_iso8601: timedelta
    :param feedback:
    :type feedback: ~azure.mgmt.iothub.models.FeedbackProperties
    """

    _validation = {
        'max_delivery_count': {'maximum': 100, 'minimum': 1},
    }

    _attribute_map = {
        'max_delivery_count': {'key': 'maxDeliveryCount', 'type': 'int'},
        'default_ttl_as_iso8601': {'key': 'defaultTtlAsIso8601', 'type': 'duration'},
        'feedback': {'key': 'feedback', 'type': 'FeedbackProperties'},
    }

    def __init__(self, **kwargs):
        super(CloudToDeviceProperties, self).__init__(**kwargs)
        self.max_delivery_count = kwargs.get('max_delivery_count', None)
        self.default_ttl_as_iso8601 = kwargs.get('default_ttl_as_iso8601', None)
        self.feedback = kwargs.get('feedback', None)


class ErrorDetails(Model):
    """Error details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar http_status_code: The HTTP status code.
    :vartype http_status_code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar details: The error details.
    :vartype details: str
    """

    _validation = {
        'code': {'readonly': True},
        'http_status_code': {'readonly': True},
        'message': {'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'Code', 'type': 'str'},
        'http_status_code': {'key': 'HttpStatusCode', 'type': 'str'},
        'message': {'key': 'Message', 'type': 'str'},
        'details': {'key': 'Details', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ErrorDetails, self).__init__(**kwargs)
        self.code = None
        self.http_status_code = None
        self.message = None
        self.details = None


class ErrorDetailsException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorDetails'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorDetailsException, self).__init__(deserialize, response, 'ErrorDetails', *args)


class EventHubConsumerGroupInfo(Model):
    """The properties of the EventHubConsumerGroupInfo object.

    :param tags: The tags.
    :type tags: dict[str, str]
    :param id: The Event Hub-compatible consumer group identifier.
    :type id: str
    :param name: The Event Hub-compatible consumer group name.
    :type name: str
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EventHubConsumerGroupInfo, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.id = kwargs.get('id', None)
        self.name = kwargs.get('name', None)


class EventHubProperties(Model):
    """The properties of the provisioned Event Hub-compatible endpoint used by the
    IoT hub.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param retention_time_in_days: The retention time for device-to-cloud
     messages in days. See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messaging#device-to-cloud-messages
    :type retention_time_in_days: long
    :param partition_count: The number of partitions for receiving
     device-to-cloud messages in the Event Hub-compatible endpoint. See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messaging#device-to-cloud-messages.
    :type partition_count: int
    :ivar partition_ids: The partition ids in the Event Hub-compatible
     endpoint.
    :vartype partition_ids: list[str]
    :ivar path: The Event Hub-compatible name.
    :vartype path: str
    :ivar endpoint: The Event Hub-compatible endpoint.
    :vartype endpoint: str
    """

    _validation = {
        'partition_ids': {'readonly': True},
        'path': {'readonly': True},
        'endpoint': {'readonly': True},
    }

    _attribute_map = {
        'retention_time_in_days': {'key': 'retentionTimeInDays', 'type': 'long'},
        'partition_count': {'key': 'partitionCount', 'type': 'int'},
        'partition_ids': {'key': 'partitionIds', 'type': '[str]'},
        'path': {'key': 'path', 'type': 'str'},
        'endpoint': {'key': 'endpoint', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EventHubProperties, self).__init__(**kwargs)
        self.retention_time_in_days = kwargs.get('retention_time_in_days', None)
        self.partition_count = kwargs.get('partition_count', None)
        self.partition_ids = None
        self.path = None
        self.endpoint = None


class ExportDevicesRequest(Model):
    """Use to provide parameters when requesting an export of all devices in the
    IoT hub.

    All required parameters must be populated in order to send to Azure.

    :param export_blob_container_uri: Required. The export blob container URI.
    :type export_blob_container_uri: str
    :param exclude_keys: Required. The value indicating whether keys should be
     excluded during export.
    :type exclude_keys: bool
    """

    _validation = {
        'export_blob_container_uri': {'required': True},
        'exclude_keys': {'required': True},
    }

    _attribute_map = {
        'export_blob_container_uri': {'key': 'ExportBlobContainerUri', 'type': 'str'},
        'exclude_keys': {'key': 'ExcludeKeys', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(ExportDevicesRequest, self).__init__(**kwargs)
        self.export_blob_container_uri = kwargs.get('export_blob_container_uri', None)
        self.exclude_keys = kwargs.get('exclude_keys', None)


class FeedbackProperties(Model):
    """The properties of the feedback queue for cloud-to-device messages.

    :param lock_duration_as_iso8601: The lock duration for the feedback queue.
     See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messaging#cloud-to-device-messages.
    :type lock_duration_as_iso8601: timedelta
    :param ttl_as_iso8601: The period of time for which a message is available
     to consume before it is expired by the IoT hub. See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messaging#cloud-to-device-messages.
    :type ttl_as_iso8601: timedelta
    :param max_delivery_count: The number of times the IoT hub attempts to
     deliver a message on the feedback queue. See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messaging#cloud-to-device-messages.
    :type max_delivery_count: int
    """

    _validation = {
        'max_delivery_count': {'maximum': 100, 'minimum': 1},
    }

    _attribute_map = {
        'lock_duration_as_iso8601': {'key': 'lockDurationAsIso8601', 'type': 'duration'},
        'ttl_as_iso8601': {'key': 'ttlAsIso8601', 'type': 'duration'},
        'max_delivery_count': {'key': 'maxDeliveryCount', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(FeedbackProperties, self).__init__(**kwargs)
        self.lock_duration_as_iso8601 = kwargs.get('lock_duration_as_iso8601', None)
        self.ttl_as_iso8601 = kwargs.get('ttl_as_iso8601', None)
        self.max_delivery_count = kwargs.get('max_delivery_count', None)


class ImportDevicesRequest(Model):
    """Use to provide parameters when requesting an import of all devices in the
    hub.

    All required parameters must be populated in order to send to Azure.

    :param input_blob_container_uri: Required. The input blob container URI.
    :type input_blob_container_uri: str
    :param output_blob_container_uri: Required. The output blob container URI.
    :type output_blob_container_uri: str
    """

    _validation = {
        'input_blob_container_uri': {'required': True},
        'output_blob_container_uri': {'required': True},
    }

    _attribute_map = {
        'input_blob_container_uri': {'key': 'InputBlobContainerUri', 'type': 'str'},
        'output_blob_container_uri': {'key': 'OutputBlobContainerUri', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ImportDevicesRequest, self).__init__(**kwargs)
        self.input_blob_container_uri = kwargs.get('input_blob_container_uri', None)
        self.output_blob_container_uri = kwargs.get('output_blob_container_uri', None)


class IotHubCapacity(Model):
    """IoT Hub capacity information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar minimum: The minimum number of units.
    :vartype minimum: long
    :ivar maximum: The maximum number of units.
    :vartype maximum: long
    :ivar default: The default number of units.
    :vartype default: long
    :ivar scale_type: The type of the scaling enabled. Possible values
     include: 'Automatic', 'Manual', 'None'
    :vartype scale_type: str or ~azure.mgmt.iothub.models.IotHubScaleType
    """

    _validation = {
        'minimum': {'readonly': True, 'maximum': 1, 'minimum': 1},
        'maximum': {'readonly': True},
        'default': {'readonly': True},
        'scale_type': {'readonly': True},
    }

    _attribute_map = {
        'minimum': {'key': 'minimum', 'type': 'long'},
        'maximum': {'key': 'maximum', 'type': 'long'},
        'default': {'key': 'default', 'type': 'long'},
        'scale_type': {'key': 'scaleType', 'type': 'IotHubScaleType'},
    }

    def __init__(self, **kwargs):
        super(IotHubCapacity, self).__init__(**kwargs)
        self.minimum = None
        self.maximum = None
        self.default = None
        self.scale_type = None


class Resource(Model):
    """The common properties of an Azure resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param location: Required. The resource location.
    :type location: str
    :param tags: The resource tags.
    :type tags: dict[str, str]
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
    }

    def __init__(self, **kwargs):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)


class IotHubDescription(Resource):
    """The description of the IoT hub.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param location: Required. The resource location.
    :type location: str
    :param tags: The resource tags.
    :type tags: dict[str, str]
    :param subscriptionid: Required. The subscription identifier.
    :type subscriptionid: str
    :param resourcegroup: Required. The name of the resource group that
     contains the IoT hub. A resource group name uniquely identifies the
     resource group within the subscription.
    :type resourcegroup: str
    :param etag: The Etag field is *not* required. If it is provided in the
     response body, it must also be provided as a header per the normal ETag
     convention.
    :type etag: str
    :param properties:
    :type properties: ~azure.mgmt.iothub.models.IotHubProperties
    :param sku: Required.
    :type sku: ~azure.mgmt.iothub.models.IotHubSkuInfo
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True, 'pattern': r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{2,49}[a-zA-Z0-9]$'},
        'type': {'readonly': True},
        'location': {'required': True},
        'subscriptionid': {'required': True},
        'resourcegroup': {'required': True},
        'sku': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'subscriptionid': {'key': 'subscriptionid', 'type': 'str'},
        'resourcegroup': {'key': 'resourcegroup', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'IotHubProperties'},
        'sku': {'key': 'sku', 'type': 'IotHubSkuInfo'},
    }

    def __init__(self, **kwargs):
        super(IotHubDescription, self).__init__(**kwargs)
        self.subscriptionid = kwargs.get('subscriptionid', None)
        self.resourcegroup = kwargs.get('resourcegroup', None)
        self.etag = kwargs.get('etag', None)
        self.properties = kwargs.get('properties', None)
        self.sku = kwargs.get('sku', None)


class IotHubNameAvailabilityInfo(Model):
    """The properties indicating whether a given IoT hub name is available.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name_available: The value which indicates whether the provided name
     is available.
    :vartype name_available: bool
    :ivar reason: The reason for unavailability. Possible values include:
     'Invalid', 'AlreadyExists'
    :vartype reason: str or
     ~azure.mgmt.iothub.models.IotHubNameUnavailabilityReason
    :param message: The detailed reason message.
    :type message: str
    """

    _validation = {
        'name_available': {'readonly': True},
        'reason': {'readonly': True},
    }

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'IotHubNameUnavailabilityReason'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(IotHubNameAvailabilityInfo, self).__init__(**kwargs)
        self.name_available = None
        self.reason = None
        self.message = kwargs.get('message', None)


class IotHubProperties(Model):
    """The properties of an IoT hub.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param authorization_policies: The shared access policies you can use to
     secure a connection to the IoT hub.
    :type authorization_policies:
     list[~azure.mgmt.iothub.models.SharedAccessSignatureAuthorizationRule]
    :param ip_filter_rules: The IP filter rules.
    :type ip_filter_rules: list[~azure.mgmt.iothub.models.IpFilterRule]
    :ivar provisioning_state: The provisioning state.
    :vartype provisioning_state: str
    :ivar host_name: The name of the host.
    :vartype host_name: str
    :param event_hub_endpoints: The Event Hub-compatible endpoint properties.
     The possible keys to this dictionary are events and
     operationsMonitoringEvents. Both of these keys have to be present in the
     dictionary while making create or update calls for the IoT hub.
    :type event_hub_endpoints: dict[str,
     ~azure.mgmt.iothub.models.EventHubProperties]
    :param storage_endpoints: The list of Azure Storage endpoints where you
     can upload files. Currently you can configure only one Azure Storage
     account and that MUST have its key as $default. Specifying more than one
     storage account causes an error to be thrown. Not specifying a value for
     this property when the enableFileUploadNotifications property is set to
     True, causes an error to be thrown.
    :type storage_endpoints: dict[str,
     ~azure.mgmt.iothub.models.StorageEndpointProperties]
    :param messaging_endpoints: The messaging endpoint properties for the file
     upload notification queue.
    :type messaging_endpoints: dict[str,
     ~azure.mgmt.iothub.models.MessagingEndpointProperties]
    :param enable_file_upload_notifications: If True, file upload
     notifications are enabled.
    :type enable_file_upload_notifications: bool
    :param cloud_to_device:
    :type cloud_to_device: ~azure.mgmt.iothub.models.CloudToDeviceProperties
    :param comments: Comments.
    :type comments: str
    :param operations_monitoring_properties:
    :type operations_monitoring_properties:
     ~azure.mgmt.iothub.models.OperationsMonitoringProperties
    :param features: The capabilities and features enabled for the IoT hub.
     Possible values include: 'None', 'DeviceManagement'
    :type features: str or ~azure.mgmt.iothub.models.Capabilities
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'host_name': {'readonly': True},
    }

    _attribute_map = {
        'authorization_policies': {'key': 'authorizationPolicies', 'type': '[SharedAccessSignatureAuthorizationRule]'},
        'ip_filter_rules': {'key': 'ipFilterRules', 'type': '[IpFilterRule]'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'host_name': {'key': 'hostName', 'type': 'str'},
        'event_hub_endpoints': {'key': 'eventHubEndpoints', 'type': '{EventHubProperties}'},
        'storage_endpoints': {'key': 'storageEndpoints', 'type': '{StorageEndpointProperties}'},
        'messaging_endpoints': {'key': 'messagingEndpoints', 'type': '{MessagingEndpointProperties}'},
        'enable_file_upload_notifications': {'key': 'enableFileUploadNotifications', 'type': 'bool'},
        'cloud_to_device': {'key': 'cloudToDevice', 'type': 'CloudToDeviceProperties'},
        'comments': {'key': 'comments', 'type': 'str'},
        'operations_monitoring_properties': {'key': 'operationsMonitoringProperties', 'type': 'OperationsMonitoringProperties'},
        'features': {'key': 'features', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(IotHubProperties, self).__init__(**kwargs)
        self.authorization_policies = kwargs.get('authorization_policies', None)
        self.ip_filter_rules = kwargs.get('ip_filter_rules', None)
        self.provisioning_state = None
        self.host_name = None
        self.event_hub_endpoints = kwargs.get('event_hub_endpoints', None)
        self.storage_endpoints = kwargs.get('storage_endpoints', None)
        self.messaging_endpoints = kwargs.get('messaging_endpoints', None)
        self.enable_file_upload_notifications = kwargs.get('enable_file_upload_notifications', None)
        self.cloud_to_device = kwargs.get('cloud_to_device', None)
        self.comments = kwargs.get('comments', None)
        self.operations_monitoring_properties = kwargs.get('operations_monitoring_properties', None)
        self.features = kwargs.get('features', None)


class IotHubQuotaMetricInfo(Model):
    """Quota metrics properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: The name of the quota metric.
    :vartype name: str
    :ivar current_value: The current value for the quota metric.
    :vartype current_value: long
    :ivar max_value: The maximum value of the quota metric.
    :vartype max_value: long
    """

    _validation = {
        'name': {'readonly': True},
        'current_value': {'readonly': True},
        'max_value': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str'},
        'current_value': {'key': 'CurrentValue', 'type': 'long'},
        'max_value': {'key': 'MaxValue', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(IotHubQuotaMetricInfo, self).__init__(**kwargs)
        self.name = None
        self.current_value = None
        self.max_value = None


class IotHubSkuDescription(Model):
    """SKU properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar resource_type: The type of the resource.
    :vartype resource_type: str
    :param sku: Required.
    :type sku: ~azure.mgmt.iothub.models.IotHubSkuInfo
    :param capacity: Required.
    :type capacity: ~azure.mgmt.iothub.models.IotHubCapacity
    """

    _validation = {
        'resource_type': {'readonly': True},
        'sku': {'required': True},
        'capacity': {'required': True},
    }

    _attribute_map = {
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'IotHubSkuInfo'},
        'capacity': {'key': 'capacity', 'type': 'IotHubCapacity'},
    }

    def __init__(self, **kwargs):
        super(IotHubSkuDescription, self).__init__(**kwargs)
        self.resource_type = None
        self.sku = kwargs.get('sku', None)
        self.capacity = kwargs.get('capacity', None)


class IotHubSkuInfo(Model):
    """Information about the SKU of the IoT hub.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the SKU. Possible values include: 'F1',
     'S1', 'S2', 'S3'
    :type name: str or ~azure.mgmt.iothub.models.IotHubSku
    :ivar tier: The billing tier for the IoT hub. Possible values include:
     'Free', 'Standard'
    :vartype tier: str or ~azure.mgmt.iothub.models.IotHubSkuTier
    :param capacity: Required. The number of provisioned IoT Hub units. See:
     https://docs.microsoft.com/azure/azure-subscription-service-limits#iot-hub-limits.
    :type capacity: long
    """

    _validation = {
        'name': {'required': True},
        'tier': {'readonly': True},
        'capacity': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'IotHubSkuTier'},
        'capacity': {'key': 'capacity', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(IotHubSkuInfo, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.tier = None
        self.capacity = kwargs.get('capacity', None)


class IpFilterRule(Model):
    """The IP filter rules for the IoT hub.

    All required parameters must be populated in order to send to Azure.

    :param filter_name: Required. The name of the IP filter rule.
    :type filter_name: str
    :param action: Required. The desired action for requests captured by this
     rule. Possible values include: 'Accept', 'Reject'
    :type action: str or ~azure.mgmt.iothub.models.IpFilterActionType
    :param ip_mask: Required. A string that contains the IP address range in
     CIDR notation for the rule.
    :type ip_mask: str
    """

    _validation = {
        'filter_name': {'required': True},
        'action': {'required': True},
        'ip_mask': {'required': True},
    }

    _attribute_map = {
        'filter_name': {'key': 'filterName', 'type': 'str'},
        'action': {'key': 'action', 'type': 'IpFilterActionType'},
        'ip_mask': {'key': 'ipMask', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(IpFilterRule, self).__init__(**kwargs)
        self.filter_name = kwargs.get('filter_name', None)
        self.action = kwargs.get('action', None)
        self.ip_mask = kwargs.get('ip_mask', None)


class JobResponse(Model):
    """The properties of the Job Response object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar job_id: The job identifier.
    :vartype job_id: str
    :ivar start_time_utc: The start time of the job.
    :vartype start_time_utc: datetime
    :ivar end_time_utc: The time the job stopped processing.
    :vartype end_time_utc: datetime
    :ivar type: The type of the job. Possible values include: 'unknown',
     'export', 'import', 'backup', 'readDeviceProperties',
     'writeDeviceProperties', 'updateDeviceConfiguration', 'rebootDevice',
     'factoryResetDevice', 'firmwareUpdate'
    :vartype type: str or ~azure.mgmt.iothub.models.JobType
    :ivar status: The status of the job. Possible values include: 'unknown',
     'enqueued', 'running', 'completed', 'failed', 'cancelled'
    :vartype status: str or ~azure.mgmt.iothub.models.JobStatus
    :ivar failure_reason: If status == failed, this string containing the
     reason for the failure.
    :vartype failure_reason: str
    :ivar status_message: The status message for the job.
    :vartype status_message: str
    :ivar parent_job_id: The job identifier of the parent job, if any.
    :vartype parent_job_id: str
    """

    _validation = {
        'job_id': {'readonly': True},
        'start_time_utc': {'readonly': True},
        'end_time_utc': {'readonly': True},
        'type': {'readonly': True},
        'status': {'readonly': True},
        'failure_reason': {'readonly': True},
        'status_message': {'readonly': True},
        'parent_job_id': {'readonly': True},
    }

    _attribute_map = {
        'job_id': {'key': 'jobId', 'type': 'str'},
        'start_time_utc': {'key': 'startTimeUtc', 'type': 'rfc-1123'},
        'end_time_utc': {'key': 'endTimeUtc', 'type': 'rfc-1123'},
        'type': {'key': 'type', 'type': 'str'},
        'status': {'key': 'status', 'type': 'JobStatus'},
        'failure_reason': {'key': 'failureReason', 'type': 'str'},
        'status_message': {'key': 'statusMessage', 'type': 'str'},
        'parent_job_id': {'key': 'parentJobId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(JobResponse, self).__init__(**kwargs)
        self.job_id = None
        self.start_time_utc = None
        self.end_time_utc = None
        self.type = None
        self.status = None
        self.failure_reason = None
        self.status_message = None
        self.parent_job_id = None


class MessagingEndpointProperties(Model):
    """The properties of the messaging endpoints used by this IoT hub.

    :param lock_duration_as_iso8601: The lock duration. See:
     https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-file-upload.
    :type lock_duration_as_iso8601: timedelta
    :param ttl_as_iso8601: The period of time for which a message is available
     to consume before it is expired by the IoT hub. See:
     https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-file-upload.
    :type ttl_as_iso8601: timedelta
    :param max_delivery_count: The number of times the IoT hub attempts to
     deliver a message. See:
     https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-file-upload.
    :type max_delivery_count: int
    """

    _validation = {
        'max_delivery_count': {'maximum': 100, 'minimum': 1},
    }

    _attribute_map = {
        'lock_duration_as_iso8601': {'key': 'lockDurationAsIso8601', 'type': 'duration'},
        'ttl_as_iso8601': {'key': 'ttlAsIso8601', 'type': 'duration'},
        'max_delivery_count': {'key': 'maxDeliveryCount', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(MessagingEndpointProperties, self).__init__(**kwargs)
        self.lock_duration_as_iso8601 = kwargs.get('lock_duration_as_iso8601', None)
        self.ttl_as_iso8601 = kwargs.get('ttl_as_iso8601', None)
        self.max_delivery_count = kwargs.get('max_delivery_count', None)


class OperationInputs(Model):
    """Input values.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the IoT hub to check.
    :type name: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OperationInputs, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)


class OperationsMonitoringProperties(Model):
    """The operations monitoring properties for the IoT hub. The possible keys to
    the dictionary are Connections, DeviceTelemetry, C2DCommands,
    DeviceIdentityOperations, FileUploadOperations.

    :param events:
    :type events: dict[str, str or
     ~azure.mgmt.iothub.models.OperationMonitoringLevel]
    """

    _attribute_map = {
        'events': {'key': 'events', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(OperationsMonitoringProperties, self).__init__(**kwargs)
        self.events = kwargs.get('events', None)


class RegistryStatistics(Model):
    """Identity registry statistics.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar total_device_count: The total count of devices in the identity
     registry.
    :vartype total_device_count: long
    :ivar enabled_device_count: The count of enabled devices in the identity
     registry.
    :vartype enabled_device_count: long
    :ivar disabled_device_count: The count of disabled devices in the identity
     registry.
    :vartype disabled_device_count: long
    """

    _validation = {
        'total_device_count': {'readonly': True},
        'enabled_device_count': {'readonly': True},
        'disabled_device_count': {'readonly': True},
    }

    _attribute_map = {
        'total_device_count': {'key': 'totalDeviceCount', 'type': 'long'},
        'enabled_device_count': {'key': 'enabledDeviceCount', 'type': 'long'},
        'disabled_device_count': {'key': 'disabledDeviceCount', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(RegistryStatistics, self).__init__(**kwargs)
        self.total_device_count = None
        self.enabled_device_count = None
        self.disabled_device_count = None


class SharedAccessSignatureAuthorizationRule(Model):
    """The properties of an IoT hub shared access policy.

    All required parameters must be populated in order to send to Azure.

    :param key_name: Required. The name of the shared access policy.
    :type key_name: str
    :param primary_key: The primary key.
    :type primary_key: str
    :param secondary_key: The secondary key.
    :type secondary_key: str
    :param rights: Required. The permissions assigned to the shared access
     policy. Possible values include: 'RegistryRead', 'RegistryWrite',
     'ServiceConnect', 'DeviceConnect', 'RegistryRead, RegistryWrite',
     'RegistryRead, ServiceConnect', 'RegistryRead, DeviceConnect',
     'RegistryWrite, ServiceConnect', 'RegistryWrite, DeviceConnect',
     'ServiceConnect, DeviceConnect', 'RegistryRead, RegistryWrite,
     ServiceConnect', 'RegistryRead, RegistryWrite, DeviceConnect',
     'RegistryRead, ServiceConnect, DeviceConnect', 'RegistryWrite,
     ServiceConnect, DeviceConnect', 'RegistryRead, RegistryWrite,
     ServiceConnect, DeviceConnect'
    :type rights: str or ~azure.mgmt.iothub.models.AccessRights
    """

    _validation = {
        'key_name': {'required': True},
        'rights': {'required': True},
    }

    _attribute_map = {
        'key_name': {'key': 'keyName', 'type': 'str'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'rights': {'key': 'rights', 'type': 'AccessRights'},
    }

    def __init__(self, **kwargs):
        super(SharedAccessSignatureAuthorizationRule, self).__init__(**kwargs)
        self.key_name = kwargs.get('key_name', None)
        self.primary_key = kwargs.get('primary_key', None)
        self.secondary_key = kwargs.get('secondary_key', None)
        self.rights = kwargs.get('rights', None)


class StorageEndpointProperties(Model):
    """The properties of the Azure Storage endpoint for file upload.

    All required parameters must be populated in order to send to Azure.

    :param sas_ttl_as_iso8601: The period of time for which the SAS URI
     generated by IoT Hub for file upload is valid. See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-file-upload#file-upload-notification-configuration-options.
    :type sas_ttl_as_iso8601: timedelta
    :param connection_string: Required. The connection string for the Azure
     Storage account to which files are uploaded.
    :type connection_string: str
    :param container_name: Required. The name of the root container where you
     upload files. The container need not exist but should be creatable using
     the connectionString specified.
    :type container_name: str
    """

    _validation = {
        'connection_string': {'required': True},
        'container_name': {'required': True},
    }

    _attribute_map = {
        'sas_ttl_as_iso8601': {'key': 'sasTtlAsIso8601', 'type': 'duration'},
        'connection_string': {'key': 'connectionString', 'type': 'str'},
        'container_name': {'key': 'containerName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(StorageEndpointProperties, self).__init__(**kwargs)
        self.sas_ttl_as_iso8601 = kwargs.get('sas_ttl_as_iso8601', None)
        self.connection_string = kwargs.get('connection_string', None)
        self.container_name = kwargs.get('container_name', None)
