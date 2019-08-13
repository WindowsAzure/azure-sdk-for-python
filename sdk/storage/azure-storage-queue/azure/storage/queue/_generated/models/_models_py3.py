# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model
from azure.core import HttpResponseError


class AccessPolicy(Model):
    """An Access policy.

    All required parameters must be populated in order to send to Azure.

    :param start: Required. the date-time the policy is active
    :type start: datetime
    :param expiry: Required. the date-time the policy expires
    :type expiry: datetime
    :param permission: Required. the permissions for the acl policy
    :type permission: str
    """

    _validation = {
        'start': {'required': True},
        'expiry': {'required': True},
        'permission': {'required': True},
    }

    _attribute_map = {
        'start': {'key': 'Start', 'type': 'iso-8601'},
        'expiry': {'key': 'Expiry', 'type': 'iso-8601'},
        'permission': {'key': 'Permission', 'type': 'str'},
    }

    def __init__(self, *, start, expiry, permission: str, **kwargs) -> None:
        super(AccessPolicy, self).__init__(**kwargs)
        self.start = start
        self.expiry = expiry
        self.permission = permission


class CorsRule(Model):
    """CORS is an HTTP feature that enables a web application running under one
    domain to access resources in another domain. Web browsers implement a
    security restriction known as same-origin policy that prevents a web page
    from calling APIs in a different domain; CORS provides a secure way to
    allow one domain (the origin domain) to call APIs in another domain.

    All required parameters must be populated in order to send to Azure.

    :param allowed_origins: Required. The origin domains that are permitted to
     make a request against the storage service via CORS. The origin domain is
     the domain from which the request originates. Note that the origin must be
     an exact case-sensitive match with the origin that the user age sends to
     the service. You can also use the wildcard character '*' to allow all
     origin domains to make requests via CORS.
    :type allowed_origins: str
    :param allowed_methods: Required. The methods (HTTP request verbs) that
     the origin domain may use for a CORS request. (comma separated)
    :type allowed_methods: str
    :param allowed_headers: Required. the request headers that the origin
     domain may specify on the CORS request.
    :type allowed_headers: str
    :param exposed_headers: Required. The response headers that may be sent in
     the response to the CORS request and exposed by the browser to the request
     issuer
    :type exposed_headers: str
    :param max_age_in_seconds: Required. The maximum amount time that a
     browser should cache the preflight OPTIONS request.
    :type max_age_in_seconds: int
    """

    _validation = {
        'allowed_origins': {'required': True},
        'allowed_methods': {'required': True},
        'allowed_headers': {'required': True},
        'exposed_headers': {'required': True},
        'max_age_in_seconds': {'required': True, 'minimum': 0},
    }

    _attribute_map = {
        'allowed_origins': {'key': 'AllowedOrigins', 'type': 'str'},
        'allowed_methods': {'key': 'AllowedMethods', 'type': 'str'},
        'allowed_headers': {'key': 'AllowedHeaders', 'type': 'str'},
        'exposed_headers': {'key': 'ExposedHeaders', 'type': 'str'},
        'max_age_in_seconds': {'key': 'MaxAgeInSeconds', 'type': 'int'},
    }

    def __init__(self, *, allowed_origins: str, allowed_methods: str, allowed_headers: str, exposed_headers: str, max_age_in_seconds: int, **kwargs) -> None:
        super(CorsRule, self).__init__(**kwargs)
        self.allowed_origins = allowed_origins
        self.allowed_methods = allowed_methods
        self.allowed_headers = allowed_headers
        self.exposed_headers = exposed_headers
        self.max_age_in_seconds = max_age_in_seconds


class DequeuedMessageItem(Model):
    """The object returned in the QueueMessageList array when calling Get Messages
    on a Queue.

    All required parameters must be populated in order to send to Azure.

    :param message_id: Required. The Id of the Message.
    :type message_id: str
    :param insertion_time: Required. The time the Message was inserted into
     the Queue.
    :type insertion_time: datetime
    :param expiration_time: Required. The time that the Message will expire
     and be automatically deleted.
    :type expiration_time: datetime
    :param pop_receipt: Required. This value is required to delete the
     Message. If deletion fails using this popreceipt then the message has been
     dequeued by another client.
    :type pop_receipt: str
    :param time_next_visible: Required. The time that the message will again
     become visible in the Queue.
    :type time_next_visible: datetime
    :param dequeue_count: Required. The number of times the message has been
     dequeued.
    :type dequeue_count: long
    :param message_text: Required. The content of the Message.
    :type message_text: str
    """

    _validation = {
        'message_id': {'required': True},
        'insertion_time': {'required': True},
        'expiration_time': {'required': True},
        'pop_receipt': {'required': True},
        'time_next_visible': {'required': True},
        'dequeue_count': {'required': True},
        'message_text': {'required': True},
    }

    _attribute_map = {
        'message_id': {'key': 'MessageId', 'type': 'str'},
        'insertion_time': {'key': 'InsertionTime', 'type': 'rfc-1123'},
        'expiration_time': {'key': 'ExpirationTime', 'type': 'rfc-1123'},
        'pop_receipt': {'key': 'PopReceipt', 'type': 'str'},
        'time_next_visible': {'key': 'TimeNextVisible', 'type': 'rfc-1123'},
        'dequeue_count': {'key': 'DequeueCount', 'type': 'long'},
        'message_text': {'key': 'MessageText', 'type': 'str'},
    }

    def __init__(self, *, message_id: str, insertion_time, expiration_time, pop_receipt: str, time_next_visible, dequeue_count: int, message_text: str, **kwargs) -> None:
        super(DequeuedMessageItem, self).__init__(**kwargs)
        self.message_id = message_id
        self.insertion_time = insertion_time
        self.expiration_time = expiration_time
        self.pop_receipt = pop_receipt
        self.time_next_visible = time_next_visible
        self.dequeue_count = dequeue_count
        self.message_text = message_text


class EnqueuedMessage(Model):
    """The object returned in the QueueMessageList array when calling Put Message
    on a Queue.

    All required parameters must be populated in order to send to Azure.

    :param message_id: Required. The Id of the Message.
    :type message_id: str
    :param insertion_time: Required. The time the Message was inserted into
     the Queue.
    :type insertion_time: datetime
    :param expiration_time: Required. The time that the Message will expire
     and be automatically deleted.
    :type expiration_time: datetime
    :param pop_receipt: Required. This value is required to delete the
     Message. If deletion fails using this popreceipt then the message has been
     dequeued by another client.
    :type pop_receipt: str
    :param time_next_visible: Required. The time that the message will again
     become visible in the Queue.
    :type time_next_visible: datetime
    """

    _validation = {
        'message_id': {'required': True},
        'insertion_time': {'required': True},
        'expiration_time': {'required': True},
        'pop_receipt': {'required': True},
        'time_next_visible': {'required': True},
    }

    _attribute_map = {
        'message_id': {'key': 'MessageId', 'type': 'str'},
        'insertion_time': {'key': 'InsertionTime', 'type': 'rfc-1123'},
        'expiration_time': {'key': 'ExpirationTime', 'type': 'rfc-1123'},
        'pop_receipt': {'key': 'PopReceipt', 'type': 'str'},
        'time_next_visible': {'key': 'TimeNextVisible', 'type': 'rfc-1123'},
    }

    def __init__(self, *, message_id: str, insertion_time, expiration_time, pop_receipt: str, time_next_visible, **kwargs) -> None:
        super(EnqueuedMessage, self).__init__(**kwargs)
        self.message_id = message_id
        self.insertion_time = insertion_time
        self.expiration_time = expiration_time
        self.pop_receipt = pop_receipt
        self.time_next_visible = time_next_visible


class GeoReplication(Model):
    """GeoReplication.

    All required parameters must be populated in order to send to Azure.

    :param status: Required. The status of the secondary location. Possible
     values include: 'live', 'bootstrap', 'unavailable'
    :type status: str or ~queue.models.GeoReplicationStatusType
    :param last_sync_time: Required. A GMT date/time value, to the second. All
     primary writes preceding this value are guaranteed to be available for
     read operations at the secondary. Primary writes after this point in time
     may or may not be available for reads.
    :type last_sync_time: datetime
    """

    _validation = {
        'status': {'required': True},
        'last_sync_time': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'Status', 'type': 'str'},
        'last_sync_time': {'key': 'LastSyncTime', 'type': 'rfc-1123'},
    }

    def __init__(self, *, status, last_sync_time, **kwargs) -> None:
        super(GeoReplication, self).__init__(**kwargs)
        self.status = status
        self.last_sync_time = last_sync_time


class ListQueuesSegmentResponse(Model):
    """The object returned when calling List Queues on a Queue Service.

    All required parameters must be populated in order to send to Azure.

    :param service_endpoint: Required.
    :type service_endpoint: str
    :param prefix: Required.
    :type prefix: str
    :param marker:
    :type marker: str
    :param max_results: Required.
    :type max_results: int
    :param queue_items:
    :type queue_items: list[~queue.models.QueueItem]
    :param next_marker: Required.
    :type next_marker: str
    """

    _validation = {
        'service_endpoint': {'required': True},
        'prefix': {'required': True},
        'max_results': {'required': True},
        'next_marker': {'required': True},
    }

    _attribute_map = {
        'service_endpoint': {'key': 'ServiceEndpoint', 'type': 'str'},
        'prefix': {'key': 'Prefix', 'type': 'str'},
        'marker': {'key': 'Marker', 'type': 'str'},
        'max_results': {'key': 'MaxResults', 'type': 'int'},
        'queue_items': {'key': 'QueueItems', 'type': '[QueueItem]'},
        'next_marker': {'key': 'NextMarker', 'type': 'str'},
    }

    def __init__(self, *, service_endpoint: str, prefix: str, max_results: int, next_marker: str, marker: str=None, queue_items=None, **kwargs) -> None:
        super(ListQueuesSegmentResponse, self).__init__(**kwargs)
        self.service_endpoint = service_endpoint
        self.prefix = prefix
        self.marker = marker
        self.max_results = max_results
        self.queue_items = queue_items
        self.next_marker = next_marker


class Logging(Model):
    """Azure Analytics Logging settings.

    All required parameters must be populated in order to send to Azure.

    :param version: Required. The version of Storage Analytics to configure.
    :type version: str
    :param delete: Required. Indicates whether all delete requests should be
     logged.
    :type delete: bool
    :param read: Required. Indicates whether all read requests should be
     logged.
    :type read: bool
    :param write: Required. Indicates whether all write requests should be
     logged.
    :type write: bool
    :param retention_policy: Required.
    :type retention_policy: ~queue.models.RetentionPolicy
    """

    _validation = {
        'version': {'required': True},
        'delete': {'required': True},
        'read': {'required': True},
        'write': {'required': True},
        'retention_policy': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'Version', 'type': 'str'},
        'delete': {'key': 'Delete', 'type': 'bool'},
        'read': {'key': 'Read', 'type': 'bool'},
        'write': {'key': 'Write', 'type': 'bool'},
        'retention_policy': {'key': 'RetentionPolicy', 'type': 'RetentionPolicy'},
    }

    def __init__(self, *, version: str, delete: bool, read: bool, write: bool, retention_policy, **kwargs) -> None:
        super(Logging, self).__init__(**kwargs)
        self.version = version
        self.delete = delete
        self.read = read
        self.write = write
        self.retention_policy = retention_policy


class Metrics(Model):
    """Metrics.

    All required parameters must be populated in order to send to Azure.

    :param version: The version of Storage Analytics to configure.
    :type version: str
    :param enabled: Required. Indicates whether metrics are enabled for the
     Queue service.
    :type enabled: bool
    :param include_apis: Indicates whether metrics should generate summary
     statistics for called API operations.
    :type include_apis: bool
    :param retention_policy:
    :type retention_policy: ~queue.models.RetentionPolicy
    """

    _validation = {
        'enabled': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'Version', 'type': 'str'},
        'enabled': {'key': 'Enabled', 'type': 'bool'},
        'include_apis': {'key': 'IncludeAPIs', 'type': 'bool'},
        'retention_policy': {'key': 'RetentionPolicy', 'type': 'RetentionPolicy'},
    }

    def __init__(self, *, enabled: bool, version: str=None, include_apis: bool=None, retention_policy=None, **kwargs) -> None:
        super(Metrics, self).__init__(**kwargs)
        self.version = version
        self.enabled = enabled
        self.include_apis = include_apis
        self.retention_policy = retention_policy


class PeekedMessageItem(Model):
    """The object returned in the QueueMessageList array when calling Peek
    Messages on a Queue.

    All required parameters must be populated in order to send to Azure.

    :param message_id: Required. The Id of the Message.
    :type message_id: str
    :param insertion_time: Required. The time the Message was inserted into
     the Queue.
    :type insertion_time: datetime
    :param expiration_time: Required. The time that the Message will expire
     and be automatically deleted.
    :type expiration_time: datetime
    :param dequeue_count: Required. The number of times the message has been
     dequeued.
    :type dequeue_count: long
    :param message_text: Required. The content of the Message.
    :type message_text: str
    """

    _validation = {
        'message_id': {'required': True},
        'insertion_time': {'required': True},
        'expiration_time': {'required': True},
        'dequeue_count': {'required': True},
        'message_text': {'required': True},
    }

    _attribute_map = {
        'message_id': {'key': 'MessageId', 'type': 'str'},
        'insertion_time': {'key': 'InsertionTime', 'type': 'rfc-1123'},
        'expiration_time': {'key': 'ExpirationTime', 'type': 'rfc-1123'},
        'dequeue_count': {'key': 'DequeueCount', 'type': 'long'},
        'message_text': {'key': 'MessageText', 'type': 'str'},
    }

    def __init__(self, *, message_id: str, insertion_time, expiration_time, dequeue_count: int, message_text: str, **kwargs) -> None:
        super(PeekedMessageItem, self).__init__(**kwargs)
        self.message_id = message_id
        self.insertion_time = insertion_time
        self.expiration_time = expiration_time
        self.dequeue_count = dequeue_count
        self.message_text = message_text


class QueueItem(Model):
    """An Azure Storage Queue.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the Queue.
    :type name: str
    :param metadata:
    :type metadata: dict[str, str]
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str'},
        'metadata': {'key': 'Metadata', 'type': '{str}'},
    }

    def __init__(self, *, name: str, metadata=None, **kwargs) -> None:
        super(QueueItem, self).__init__(**kwargs)
        self.name = name
        self.metadata = metadata


class QueueMessage(Model):
    """A Message object which can be stored in a Queue.

    All required parameters must be populated in order to send to Azure.

    :param message_text: Required. The content of the message
    :type message_text: str
    """

    _validation = {
        'message_text': {'required': True},
    }

    _attribute_map = {
        'message_text': {'key': 'MessageText', 'type': 'str'},
    }

    def __init__(self, *, message_text: str, **kwargs) -> None:
        super(QueueMessage, self).__init__(**kwargs)
        self.message_text = message_text


class RetentionPolicy(Model):
    """the retention policy.

    All required parameters must be populated in order to send to Azure.

    :param enabled: Required. Indicates whether a retention policy is enabled
     for the storage service
    :type enabled: bool
    :param days: Indicates the number of days that metrics or logging or
     soft-deleted data should be retained. All data older than this value will
     be deleted
    :type days: int
    """

    _validation = {
        'enabled': {'required': True},
        'days': {'minimum': 1},
    }

    _attribute_map = {
        'enabled': {'key': 'Enabled', 'type': 'bool'},
        'days': {'key': 'Days', 'type': 'int'},
    }

    def __init__(self, *, enabled: bool, days: int=None, **kwargs) -> None:
        super(RetentionPolicy, self).__init__(**kwargs)
        self.enabled = enabled
        self.days = days


class SignedIdentifier(Model):
    """signed identifier.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. a unique id
    :type id: str
    :param access_policy: Required. The access policy
    :type access_policy: ~queue.models.AccessPolicy
    """

    _validation = {
        'id': {'required': True},
        'access_policy': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'Id', 'type': 'str'},
        'access_policy': {'key': 'AccessPolicy', 'type': 'AccessPolicy'},
    }

    def __init__(self, *, id: str, access_policy, **kwargs) -> None:
        super(SignedIdentifier, self).__init__(**kwargs)
        self.id = id
        self.access_policy = access_policy


class StorageError(Model):
    """StorageError.

    :param message:
    :type message: str
    """

    _attribute_map = {
        'message': {'key': 'Message', 'type': 'str'},
    }

    def __init__(self, *, message: str=None, **kwargs) -> None:
        super(StorageError, self).__init__(**kwargs)
        self.message = message


class StorageErrorException(HttpResponseError):
    """Server responsed with exception of type: 'StorageError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, response, deserialize, *args):

      model_name = 'StorageError'
      self.error = deserialize(model_name, response)
      if self.error is None:
          self.error = deserialize.dependencies[model_name]()
      super(StorageErrorException, self).__init__(response=response)


class StorageServiceProperties(Model):
    """Storage Service Properties.

    :param logging: Azure Analytics Logging settings
    :type logging: ~queue.models.Logging
    :param hour_metrics: A summary of request statistics grouped by API in
     hourly aggregates for queues
    :type hour_metrics: ~queue.models.Metrics
    :param minute_metrics: a summary of request statistics grouped by API in
     minute aggregates for queues
    :type minute_metrics: ~queue.models.Metrics
    :param cors: The set of CORS rules.
    :type cors: list[~queue.models.CorsRule]
    """

    _attribute_map = {
        'logging': {'key': 'Logging', 'type': 'Logging'},
        'hour_metrics': {'key': 'HourMetrics', 'type': 'Metrics'},
        'minute_metrics': {'key': 'MinuteMetrics', 'type': 'Metrics'},
        'cors': {'key': 'Cors', 'type': '[CorsRule]'},
    }

    def __init__(self, *, logging=None, hour_metrics=None, minute_metrics=None, cors=None, **kwargs) -> None:
        super(StorageServiceProperties, self).__init__(**kwargs)
        self.logging = logging
        self.hour_metrics = hour_metrics
        self.minute_metrics = minute_metrics
        self.cors = cors


class StorageServiceStats(Model):
    """Stats for the storage service.

    :param geo_replication: Geo-Replication information for the Secondary
     Storage Service
    :type geo_replication: ~queue.models.GeoReplication
    """

    _attribute_map = {
        'geo_replication': {'key': 'GeoReplication', 'type': 'GeoReplication'},
    }

    def __init__(self, *, geo_replication=None, **kwargs) -> None:
        super(StorageServiceStats, self).__init__(**kwargs)
        self.geo_replication = geo_replication
