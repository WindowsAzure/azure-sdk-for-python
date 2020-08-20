# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import datetime
from typing import Dict, Optional

import msrest.serialization


class CloudEvent(msrest.serialization.Model):
    """Properties of an event published to an Event Grid topic using the CloudEvent 1.0 Schema.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param id: Required. An identifier for the event. The combination of id and source must be
     unique for each distinct event.
    :type id: str
    :param source: Required. Identifies the context in which an event happened. The combination of
     id and source must be unique for each distinct event.
    :type source: str
    :param data: Event data specific to the event type.
    :type data: object
    :param data_base64: Event data specific to the event type, encoded as a base64 string.
    :type data_base64: bytearray
    :param type: Required. Type of event related to the originating occurrence.
    :type type: str
    :param time: The time (in UTC) the event was generated, in RFC3339 format.
    :type time: ~datetime.datetime
    :param specversion: Required. The version of the CloudEvents specification which the event
     uses.
    :type specversion: str
    :param dataschema: Identifies the schema that data adheres to.
    :type dataschema: str
    :param datacontenttype: Content type of data value.
    :type datacontenttype: str
    :param subject: This describes the subject of the event in the context of the event producer
     (identified by source).
    :type subject: str
    """

    _validation = {
        'id': {'required': True},
        'source': {'required': True},
        'type': {'required': True},
        'specversion': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'id': {'key': 'id', 'type': 'str'},
        'source': {'key': 'source', 'type': 'str'},
        'data': {'key': 'data', 'type': 'object'},
        'data_base64': {'key': 'data_base64', 'type': 'bytearray'},
        'type': {'key': 'type', 'type': 'str'},
        'time': {'key': 'time', 'type': 'iso-8601'},
        'specversion': {'key': 'specversion', 'type': 'str'},
        'dataschema': {'key': 'dataschema', 'type': 'str'},
        'datacontenttype': {'key': 'datacontenttype', 'type': 'str'},
        'subject': {'key': 'subject', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: str,
        source: str,
        type: str,
        specversion: str,
        additional_properties: Optional[Dict[str, object]] = None,
        data: Optional[object] = None,
        data_base64: Optional[bytearray] = None,
        time: Optional[datetime.datetime] = None,
        dataschema: Optional[str] = None,
        datacontenttype: Optional[str] = None,
        subject: Optional[str] = None,
        **kwargs
    ):
        super(CloudEvent, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.id = id
        self.source = source
        self.data = data
        self.data_base64 = data_base64
        self.type = type
        self.time = time
        self.specversion = specversion
        self.dataschema = dataschema
        self.datacontenttype = datacontenttype
        self.subject = subject


class EventGridEvent(msrest.serialization.Model):
    """Properties of an event published to an Event Grid topic using the EventGrid Schema.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. An unique identifier for the event.
    :type id: str
    :param topic: The resource path of the event source.
    :type topic: str
    :param subject: Required. A resource path relative to the topic path.
    :type subject: str
    :param data: Required. Event data specific to the event type.
    :type data: object
    :param event_type: Required. The type of the event that occurred.
    :type event_type: str
    :param event_time: Required. The time (in UTC) the event was generated.
    :type event_time: ~datetime.datetime
    :ivar metadata_version: The schema version of the event metadata.
    :vartype metadata_version: str
    :param data_version: Required. The schema version of the data object.
    :type data_version: str
    """

    _validation = {
        'id': {'required': True},
        'subject': {'required': True},
        'data': {'required': True},
        'event_type': {'required': True},
        'event_time': {'required': True},
        'metadata_version': {'readonly': True},
        'data_version': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'topic': {'key': 'topic', 'type': 'str'},
        'subject': {'key': 'subject', 'type': 'str'},
        'data': {'key': 'data', 'type': 'object'},
        'event_type': {'key': 'eventType', 'type': 'str'},
        'event_time': {'key': 'eventTime', 'type': 'iso-8601'},
        'metadata_version': {'key': 'metadataVersion', 'type': 'str'},
        'data_version': {'key': 'dataVersion', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: str,
        subject: str,
        data: object,
        event_type: str,
        event_time: datetime.datetime,
        data_version: str,
        topic: Optional[str] = None,
        **kwargs
    ):
        super(EventGridEvent, self).__init__(**kwargs)
        self.id = id
        self.topic = topic
        self.subject = subject
        self.data = data
        self.event_type = event_type
        self.event_time = event_time
        self.metadata_version = None
        self.data_version = data_version


class StorageBlobCreatedEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for an Microsoft.Storage.BlobCreated event.

    :param api: The name of the API/operation that triggered this event.
    :type api: str
    :param client_request_id: A request id provided by the client of the storage API operation that
     triggered this event.
    :type client_request_id: str
    :param request_id: The request id generated by the Storage service for the storage API
     operation that triggered this event.
    :type request_id: str
    :param e_tag: The etag of the blob at the time this event was triggered.
    :type e_tag: str
    :param content_type: The content type of the blob. This is the same as what would be returned
     in the Content-Type header from the blob.
    :type content_type: str
    :param content_length: The size of the blob in bytes. This is the same as what would be
     returned in the Content-Length header from the blob.
    :type content_length: long
    :param content_offset: The offset of the blob in bytes.
    :type content_offset: long
    :param blob_type: The type of blob.
    :type blob_type: str
    :param url: The path to the blob.
    :type url: str
    :param sequencer: An opaque string value representing the logical sequence of events for any
     particular blob name. Users can use standard string comparison to understand the relative
     sequence of two events on the same blob name.
    :type sequencer: str
    :param identity: The identity of the requester that triggered this event.
    :type identity: str
    :param storage_diagnostics: For service use only. Diagnostic data occasionally included by the
     Azure Storage service. This property should be ignored by event consumers.
    :type storage_diagnostics: object
    """

    _attribute_map = {
        'api': {'key': 'api', 'type': 'str'},
        'client_request_id': {'key': 'clientRequestId', 'type': 'str'},
        'request_id': {'key': 'requestId', 'type': 'str'},
        'e_tag': {'key': 'eTag', 'type': 'str'},
        'content_type': {'key': 'contentType', 'type': 'str'},
        'content_length': {'key': 'contentLength', 'type': 'long'},
        'content_offset': {'key': 'contentOffset', 'type': 'long'},
        'blob_type': {'key': 'blobType', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'sequencer': {'key': 'sequencer', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'str'},
        'storage_diagnostics': {'key': 'storageDiagnostics', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        api: Optional[str] = None,
        client_request_id: Optional[str] = None,
        request_id: Optional[str] = None,
        e_tag: Optional[str] = None,
        content_type: Optional[str] = None,
        content_length: Optional[int] = None,
        content_offset: Optional[int] = None,
        blob_type: Optional[str] = None,
        url: Optional[str] = None,
        sequencer: Optional[str] = None,
        identity: Optional[str] = None,
        storage_diagnostics: Optional[object] = None,
        **kwargs
    ):
        super(StorageBlobCreatedEventData, self).__init__(**kwargs)
        self.api = api
        self.client_request_id = client_request_id
        self.request_id = request_id
        self.e_tag = e_tag
        self.content_type = content_type
        self.content_length = content_length
        self.content_offset = content_offset
        self.blob_type = blob_type
        self.url = url
        self.sequencer = sequencer
        self.identity = identity
        self.storage_diagnostics = storage_diagnostics


class StorageBlobDeletedEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for an Microsoft.Storage.BlobDeleted event.

    :param api: The name of the API/operation that triggered this event.
    :type api: str
    :param client_request_id: A request id provided by the client of the storage API operation that
     triggered this event.
    :type client_request_id: str
    :param request_id: The request id generated by the Storage service for the storage API
     operation that triggered this event.
    :type request_id: str
    :param content_type: The content type of the blob. This is the same as what would be returned
     in the Content-Type header from the blob.
    :type content_type: str
    :param blob_type: The type of blob.
    :type blob_type: str
    :param url: The path to the blob.
    :type url: str
    :param sequencer: An opaque string value representing the logical sequence of events for any
     particular blob name. Users can use standard string comparison to understand the relative
     sequence of two events on the same blob name.
    :type sequencer: str
    :param identity: The identity of the requester that triggered this event.
    :type identity: str
    :param storage_diagnostics: For service use only. Diagnostic data occasionally included by the
     Azure Storage service. This property should be ignored by event consumers.
    :type storage_diagnostics: object
    """

    _attribute_map = {
        'api': {'key': 'api', 'type': 'str'},
        'client_request_id': {'key': 'clientRequestId', 'type': 'str'},
        'request_id': {'key': 'requestId', 'type': 'str'},
        'content_type': {'key': 'contentType', 'type': 'str'},
        'blob_type': {'key': 'blobType', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'sequencer': {'key': 'sequencer', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'str'},
        'storage_diagnostics': {'key': 'storageDiagnostics', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        api: Optional[str] = None,
        client_request_id: Optional[str] = None,
        request_id: Optional[str] = None,
        content_type: Optional[str] = None,
        blob_type: Optional[str] = None,
        url: Optional[str] = None,
        sequencer: Optional[str] = None,
        identity: Optional[str] = None,
        storage_diagnostics: Optional[object] = None,
        **kwargs
    ):
        super(StorageBlobDeletedEventData, self).__init__(**kwargs)
        self.api = api
        self.client_request_id = client_request_id
        self.request_id = request_id
        self.content_type = content_type
        self.blob_type = blob_type
        self.url = url
        self.sequencer = sequencer
        self.identity = identity
        self.storage_diagnostics = storage_diagnostics


class StorageBlobRenamedEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for an Microsoft.Storage.BlobRenamed event.

    :param api: The name of the API/operation that triggered this event.
    :type api: str
    :param client_request_id: A request id provided by the client of the storage API operation that
     triggered this event.
    :type client_request_id: str
    :param request_id: The request id generated by the storage service for the storage API
     operation that triggered this event.
    :type request_id: str
    :param source_url: The path to the blob that was renamed.
    :type source_url: str
    :param destination_url: The new path to the blob after the rename operation.
    :type destination_url: str
    :param sequencer: An opaque string value representing the logical sequence of events for any
     particular blob name. Users can use standard string comparison to understand the relative
     sequence of two events on the same blob name.
    :type sequencer: str
    :param identity: The identity of the requester that triggered this event.
    :type identity: str
    :param storage_diagnostics: For service use only. Diagnostic data occasionally included by the
     Azure Storage service. This property should be ignored by event consumers.
    :type storage_diagnostics: object
    """

    _attribute_map = {
        'api': {'key': 'api', 'type': 'str'},
        'client_request_id': {'key': 'clientRequestId', 'type': 'str'},
        'request_id': {'key': 'requestId', 'type': 'str'},
        'source_url': {'key': 'sourceUrl', 'type': 'str'},
        'destination_url': {'key': 'destinationUrl', 'type': 'str'},
        'sequencer': {'key': 'sequencer', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'str'},
        'storage_diagnostics': {'key': 'storageDiagnostics', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        api: Optional[str] = None,
        client_request_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_url: Optional[str] = None,
        destination_url: Optional[str] = None,
        sequencer: Optional[str] = None,
        identity: Optional[str] = None,
        storage_diagnostics: Optional[object] = None,
        **kwargs
    ):
        super(StorageBlobRenamedEventData, self).__init__(**kwargs)
        self.api = api
        self.client_request_id = client_request_id
        self.request_id = request_id
        self.source_url = source_url
        self.destination_url = destination_url
        self.sequencer = sequencer
        self.identity = identity
        self.storage_diagnostics = storage_diagnostics


class StorageDirectoryCreatedEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for an Microsoft.Storage.DirectoryCreated event.

    :param api: The name of the API/operation that triggered this event.
    :type api: str
    :param client_request_id: A request id provided by the client of the storage API operation that
     triggered this event.
    :type client_request_id: str
    :param request_id: The request id generated by the storage service for the storage API
     operation that triggered this event.
    :type request_id: str
    :param e_tag: The etag of the directory at the time this event was triggered.
    :type e_tag: str
    :param url: The path to the directory.
    :type url: str
    :param sequencer: An opaque string value representing the logical sequence of events for any
     particular directory name. Users can use standard string comparison to understand the relative
     sequence of two events on the same directory name.
    :type sequencer: str
    :param identity: The identity of the requester that triggered this event.
    :type identity: str
    :param storage_diagnostics: For service use only. Diagnostic data occasionally included by the
     Azure Storage service. This property should be ignored by event consumers.
    :type storage_diagnostics: object
    """

    _attribute_map = {
        'api': {'key': 'api', 'type': 'str'},
        'client_request_id': {'key': 'clientRequestId', 'type': 'str'},
        'request_id': {'key': 'requestId', 'type': 'str'},
        'e_tag': {'key': 'eTag', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'sequencer': {'key': 'sequencer', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'str'},
        'storage_diagnostics': {'key': 'storageDiagnostics', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        api: Optional[str] = None,
        client_request_id: Optional[str] = None,
        request_id: Optional[str] = None,
        e_tag: Optional[str] = None,
        url: Optional[str] = None,
        sequencer: Optional[str] = None,
        identity: Optional[str] = None,
        storage_diagnostics: Optional[object] = None,
        **kwargs
    ):
        super(StorageDirectoryCreatedEventData, self).__init__(**kwargs)
        self.api = api
        self.client_request_id = client_request_id
        self.request_id = request_id
        self.e_tag = e_tag
        self.url = url
        self.sequencer = sequencer
        self.identity = identity
        self.storage_diagnostics = storage_diagnostics


class StorageDirectoryDeletedEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for an Microsoft.Storage.DirectoryDeleted event.

    :param api: The name of the API/operation that triggered this event.
    :type api: str
    :param client_request_id: A request id provided by the client of the storage API operation that
     triggered this event.
    :type client_request_id: str
    :param request_id: The request id generated by the storage service for the storage API
     operation that triggered this event.
    :type request_id: str
    :param url: The path to the deleted directory.
    :type url: str
    :param recursive: Is this event for a recursive delete operation.
    :type recursive: bool
    :param sequencer: An opaque string value representing the logical sequence of events for any
     particular directory name. Users can use standard string comparison to understand the relative
     sequence of two events on the same directory name.
    :type sequencer: str
    :param identity: The identity of the requester that triggered this event.
    :type identity: str
    :param storage_diagnostics: For service use only. Diagnostic data occasionally included by the
     Azure Storage service. This property should be ignored by event consumers.
    :type storage_diagnostics: object
    """

    _attribute_map = {
        'api': {'key': 'api', 'type': 'str'},
        'client_request_id': {'key': 'clientRequestId', 'type': 'str'},
        'request_id': {'key': 'requestId', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'recursive': {'key': 'recursive', 'type': 'bool'},
        'sequencer': {'key': 'sequencer', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'str'},
        'storage_diagnostics': {'key': 'storageDiagnostics', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        api: Optional[str] = None,
        client_request_id: Optional[str] = None,
        request_id: Optional[str] = None,
        url: Optional[str] = None,
        recursive: Optional[bool] = None,
        sequencer: Optional[str] = None,
        identity: Optional[str] = None,
        storage_diagnostics: Optional[object] = None,
        **kwargs
    ):
        super(StorageDirectoryDeletedEventData, self).__init__(**kwargs)
        self.api = api
        self.client_request_id = client_request_id
        self.request_id = request_id
        self.url = url
        self.recursive = recursive
        self.sequencer = sequencer
        self.identity = identity
        self.storage_diagnostics = storage_diagnostics


class StorageDirectoryRenamedEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for an Microsoft.Storage.DirectoryRenamed event.

    :param api: The name of the API/operation that triggered this event.
    :type api: str
    :param client_request_id: A request id provided by the client of the storage API operation that
     triggered this event.
    :type client_request_id: str
    :param request_id: The request id generated by the storage service for the storage API
     operation that triggered this event.
    :type request_id: str
    :param source_url: The path to the directory that was renamed.
    :type source_url: str
    :param destination_url: The new path to the directory after the rename operation.
    :type destination_url: str
    :param sequencer: An opaque string value representing the logical sequence of events for any
     particular directory name. Users can use standard string comparison to understand the relative
     sequence of two events on the same directory name.
    :type sequencer: str
    :param identity: The identity of the requester that triggered this event.
    :type identity: str
    :param storage_diagnostics: For service use only. Diagnostic data occasionally included by the
     Azure Storage service. This property should be ignored by event consumers.
    :type storage_diagnostics: object
    """

    _attribute_map = {
        'api': {'key': 'api', 'type': 'str'},
        'client_request_id': {'key': 'clientRequestId', 'type': 'str'},
        'request_id': {'key': 'requestId', 'type': 'str'},
        'source_url': {'key': 'sourceUrl', 'type': 'str'},
        'destination_url': {'key': 'destinationUrl', 'type': 'str'},
        'sequencer': {'key': 'sequencer', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'str'},
        'storage_diagnostics': {'key': 'storageDiagnostics', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        api: Optional[str] = None,
        client_request_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_url: Optional[str] = None,
        destination_url: Optional[str] = None,
        sequencer: Optional[str] = None,
        identity: Optional[str] = None,
        storage_diagnostics: Optional[object] = None,
        **kwargs
    ):
        super(StorageDirectoryRenamedEventData, self).__init__(**kwargs)
        self.api = api
        self.client_request_id = client_request_id
        self.request_id = request_id
        self.source_url = source_url
        self.destination_url = destination_url
        self.sequencer = sequencer
        self.identity = identity
        self.storage_diagnostics = storage_diagnostics


class StorageLifecyclePolicyActionSummaryDetail(msrest.serialization.Model):
    """Execution statistics of a specific policy action in a Blob Management cycle.

    :param total_objects_count: Total number of objects to be acted on by this action.
    :type total_objects_count: long
    :param success_count: Number of success operations of this action.
    :type success_count: long
    :param error_list: Error messages of this action if any.
    :type error_list: str
    """

    _attribute_map = {
        'total_objects_count': {'key': 'totalObjectsCount', 'type': 'long'},
        'success_count': {'key': 'successCount', 'type': 'long'},
        'error_list': {'key': 'errorList', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        total_objects_count: Optional[int] = None,
        success_count: Optional[int] = None,
        error_list: Optional[str] = None,
        **kwargs
    ):
        super(StorageLifecyclePolicyActionSummaryDetail, self).__init__(**kwargs)
        self.total_objects_count = total_objects_count
        self.success_count = success_count
        self.error_list = error_list


class StorageLifecyclePolicyCompletedEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for an Microsoft.Storage.LifecyclePolicyCompleted event.

    :param schedule_time: The time the policy task was scheduled.
    :type schedule_time: str
    :param delete_summary: Execution statistics of a specific policy action in a Blob Management
     cycle.
    :type delete_summary:
     ~event_grid_publisher_client.models.StorageLifecyclePolicyActionSummaryDetail
    :param tier_to_cool_summary: Execution statistics of a specific policy action in a Blob
     Management cycle.
    :type tier_to_cool_summary:
     ~event_grid_publisher_client.models.StorageLifecyclePolicyActionSummaryDetail
    :param tier_to_archive_summary: Execution statistics of a specific policy action in a Blob
     Management cycle.
    :type tier_to_archive_summary:
     ~event_grid_publisher_client.models.StorageLifecyclePolicyActionSummaryDetail
    """

    _attribute_map = {
        'schedule_time': {'key': 'scheduleTime', 'type': 'str'},
        'delete_summary': {'key': 'deleteSummary', 'type': 'StorageLifecyclePolicyActionSummaryDetail'},
        'tier_to_cool_summary': {'key': 'tierToCoolSummary', 'type': 'StorageLifecyclePolicyActionSummaryDetail'},
        'tier_to_archive_summary': {'key': 'tierToArchiveSummary', 'type': 'StorageLifecyclePolicyActionSummaryDetail'},
    }

    def __init__(
        self,
        *,
        schedule_time: Optional[str] = None,
        delete_summary: Optional["StorageLifecyclePolicyActionSummaryDetail"] = None,
        tier_to_cool_summary: Optional["StorageLifecyclePolicyActionSummaryDetail"] = None,
        tier_to_archive_summary: Optional["StorageLifecyclePolicyActionSummaryDetail"] = None,
        **kwargs
    ):
        super(StorageLifecyclePolicyCompletedEventData, self).__init__(**kwargs)
        self.schedule_time = schedule_time
        self.delete_summary = delete_summary
        self.tier_to_cool_summary = tier_to_cool_summary
        self.tier_to_archive_summary = tier_to_archive_summary


class SubscriptionDeletedEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for a Microsoft.EventGrid.SubscriptionDeletedEvent.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar event_subscription_id: The Azure resource ID of the deleted event subscription.
    :vartype event_subscription_id: str
    """

    _validation = {
        'event_subscription_id': {'readonly': True},
    }

    _attribute_map = {
        'event_subscription_id': {'key': 'eventSubscriptionId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SubscriptionDeletedEventData, self).__init__(**kwargs)
        self.event_subscription_id = None


class SubscriptionValidationEventData(msrest.serialization.Model):
    """Schema of the Data property of an EventGridEvent for a Microsoft.EventGrid.SubscriptionValidationEvent.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar validation_code: The validation code sent by Azure Event Grid to validate an event
     subscription. To complete the validation handshake, the subscriber must either respond with
     this validation code as part of the validation response, or perform a GET request on the
     validationUrl (available starting version 2018-05-01-preview).
    :vartype validation_code: str
    :ivar validation_url: The validation URL sent by Azure Event Grid (available starting version
     2018-05-01-preview). To complete the validation handshake, the subscriber must either respond
     with the validationCode as part of the validation response, or perform a GET request on the
     validationUrl (available starting version 2018-05-01-preview).
    :vartype validation_url: str
    """

    _validation = {
        'validation_code': {'readonly': True},
        'validation_url': {'readonly': True},
    }

    _attribute_map = {
        'validation_code': {'key': 'validationCode', 'type': 'str'},
        'validation_url': {'key': 'validationUrl', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SubscriptionValidationEventData, self).__init__(**kwargs)
        self.validation_code = None
        self.validation_url = None


class SubscriptionValidationResponse(msrest.serialization.Model):
    """To complete an event subscription validation handshake, a subscriber can use either the validationCode or the validationUrl received in a SubscriptionValidationEvent. When the validationCode is used, the SubscriptionValidationResponse can be used to build the response.

    :param validation_response: The validation response sent by the subscriber to Azure Event Grid
     to complete the validation of an event subscription.
    :type validation_response: str
    """

    _attribute_map = {
        'validation_response': {'key': 'validationResponse', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        validation_response: Optional[str] = None,
        **kwargs
    ):
        super(SubscriptionValidationResponse, self).__init__(**kwargs)
        self.validation_response = validation_response
