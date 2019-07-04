# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------
# pylint: skip-file

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
        'start': {'key': 'Start', 'type': 'str', 'xml': {'name': 'Start'}},
        'expiry': {'key': 'Expiry', 'type': 'str', 'xml': {'name': 'Expiry'}},
        'permission': {'key': 'Permission', 'type': 'str', 'xml': {'name': 'Permission'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(AccessPolicy, self).__init__(**kwargs)
        self.start = kwargs.get('start', None)
        self.expiry = kwargs.get('expiry', None)
        self.permission = kwargs.get('permission', None)


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
        'allowed_origins': {'key': 'AllowedOrigins', 'type': 'str', 'xml': {'name': 'AllowedOrigins'}},
        'allowed_methods': {'key': 'AllowedMethods', 'type': 'str', 'xml': {'name': 'AllowedMethods'}},
        'allowed_headers': {'key': 'AllowedHeaders', 'type': 'str', 'xml': {'name': 'AllowedHeaders'}},
        'exposed_headers': {'key': 'ExposedHeaders', 'type': 'str', 'xml': {'name': 'ExposedHeaders'}},
        'max_age_in_seconds': {'key': 'MaxAgeInSeconds', 'type': 'int', 'xml': {'name': 'MaxAgeInSeconds'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(CorsRule, self).__init__(**kwargs)
        self.allowed_origins = kwargs.get('allowed_origins', None)
        self.allowed_methods = kwargs.get('allowed_methods', None)
        self.allowed_headers = kwargs.get('allowed_headers', None)
        self.exposed_headers = kwargs.get('exposed_headers', None)
        self.max_age_in_seconds = kwargs.get('max_age_in_seconds', None)


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
        'message_id': {'key': 'MessageId', 'type': 'str', 'xml': {'name': 'MessageId'}},
        'insertion_time': {'key': 'InsertionTime', 'type': 'rfc-1123', 'xml': {'name': 'InsertionTime'}},
        'expiration_time': {'key': 'ExpirationTime', 'type': 'rfc-1123', 'xml': {'name': 'ExpirationTime'}},
        'pop_receipt': {'key': 'PopReceipt', 'type': 'str', 'xml': {'name': 'PopReceipt'}},
        'time_next_visible': {'key': 'TimeNextVisible', 'type': 'rfc-1123', 'xml': {'name': 'TimeNextVisible'}},
        'dequeue_count': {'key': 'DequeueCount', 'type': 'long', 'xml': {'name': 'DequeueCount'}},
        'message_text': {'key': 'MessageText', 'type': 'str', 'xml': {'name': 'MessageText'}},
    }

    _xml_map = {
        'name': 'QueueMessage'
    }

    def __init__(self, **kwargs):
        super(DequeuedMessageItem, self).__init__(**kwargs)
        self.message_id = kwargs.get('message_id', None)
        self.insertion_time = kwargs.get('insertion_time', None)
        self.expiration_time = kwargs.get('expiration_time', None)
        self.pop_receipt = kwargs.get('pop_receipt', None)
        self.time_next_visible = kwargs.get('time_next_visible', None)
        self.dequeue_count = kwargs.get('dequeue_count', None)
        self.message_text = kwargs.get('message_text', None)


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
        'message_id': {'key': 'MessageId', 'type': 'str', 'xml': {'name': 'MessageId'}},
        'insertion_time': {'key': 'InsertionTime', 'type': 'rfc-1123', 'xml': {'name': 'InsertionTime'}},
        'expiration_time': {'key': 'ExpirationTime', 'type': 'rfc-1123', 'xml': {'name': 'ExpirationTime'}},
        'pop_receipt': {'key': 'PopReceipt', 'type': 'str', 'xml': {'name': 'PopReceipt'}},
        'time_next_visible': {'key': 'TimeNextVisible', 'type': 'rfc-1123', 'xml': {'name': 'TimeNextVisible'}},
    }

    _xml_map = {
        'name': 'QueueMessage'
    }

    def __init__(self, **kwargs):
        super(EnqueuedMessage, self).__init__(**kwargs)
        self.message_id = kwargs.get('message_id', None)
        self.insertion_time = kwargs.get('insertion_time', None)
        self.expiration_time = kwargs.get('expiration_time', None)
        self.pop_receipt = kwargs.get('pop_receipt', None)
        self.time_next_visible = kwargs.get('time_next_visible', None)


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
        'status': {'key': 'Status', 'type': 'str', 'xml': {'name': 'Status'}},
        'last_sync_time': {'key': 'LastSyncTime', 'type': 'rfc-1123', 'xml': {'name': 'LastSyncTime'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(GeoReplication, self).__init__(**kwargs)
        self.status = kwargs.get('status', None)
        self.last_sync_time = kwargs.get('last_sync_time', None)


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
        'service_endpoint': {'key': 'ServiceEndpoint', 'type': 'str', 'xml': {'name': 'ServiceEndpoint', 'attr': True}},
        'prefix': {'key': 'Prefix', 'type': 'str', 'xml': {'name': 'Prefix'}},
        'marker': {'key': 'Marker', 'type': 'str', 'xml': {'name': 'Marker'}},
        'max_results': {'key': 'MaxResults', 'type': 'int', 'xml': {'name': 'MaxResults'}},
        'queue_items': {'key': 'QueueItems', 'type': '[QueueItem]', 'xml': {'name': 'Queues', 'itemsName': 'Queues', 'wrapped': True}},
        'next_marker': {'key': 'NextMarker', 'type': 'str', 'xml': {'name': 'NextMarker'}},
    }

    def __init__(self, **kwargs):
        super(ListQueuesSegmentResponse, self).__init__(**kwargs)
        self.service_endpoint = kwargs.get('service_endpoint', None)
        self.prefix = kwargs.get('prefix', None)
        self.marker = kwargs.get('marker', None)
        self.max_results = kwargs.get('max_results', None)
        self.queue_items = kwargs.get('queue_items', None)
        self.next_marker = kwargs.get('next_marker', None)


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
        'version': {'key': 'Version', 'type': 'str', 'xml': {'name': 'Version'}},
        'delete': {'key': 'Delete', 'type': 'bool', 'xml': {'name': 'Delete'}},
        'read': {'key': 'Read', 'type': 'bool', 'xml': {'name': 'Read'}},
        'write': {'key': 'Write', 'type': 'bool', 'xml': {'name': 'Write'}},
        'retention_policy': {'key': 'RetentionPolicy', 'type': 'RetentionPolicy', 'xml': {'name': 'RetentionPolicy'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(Logging, self).__init__(**kwargs)
        self.version = kwargs.get('version', None)
        self.delete = kwargs.get('delete', None)
        self.read = kwargs.get('read', None)
        self.write = kwargs.get('write', None)
        self.retention_policy = kwargs.get('retention_policy', None)


class Metrics(Model):
    """Metrics.

    All required parameters must be populated in order to send to Azure.

    :param version: The version of Storage Analytics to configure.
    :type version: str
    :param enabled: Required. Indicates whether metrics are enabled for the
     Queue service.
    :type enabled: bool
    :param include_ap_is: Indicates whether metrics should generate summary
     statistics for called API operations.
    :type include_ap_is: bool
    :param retention_policy:
    :type retention_policy: ~queue.models.RetentionPolicy
    """

    _validation = {
        'enabled': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'Version', 'type': 'str', 'xml': {'name': 'Version'}},
        'enabled': {'key': 'Enabled', 'type': 'bool', 'xml': {'name': 'Enabled'}},
        'include_apis': {'key': 'IncludeAPIs', 'type': 'bool', 'xml': {'name': 'IncludeAPIs'}},
        'retention_policy': {'key': 'RetentionPolicy', 'type': 'RetentionPolicy', 'xml': {'name': 'RetentionPolicy'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(Metrics, self).__init__(**kwargs)
        self.version = kwargs.get('version', None)
        self.enabled = kwargs.get('enabled', None)
        self.include_ap_is = kwargs.get('include_ap_is', None)
        self.retention_policy = kwargs.get('retention_policy', None)


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
        'message_id': {'key': 'MessageId', 'type': 'str', 'xml': {'name': 'MessageId'}},
        'insertion_time': {'key': 'InsertionTime', 'type': 'rfc-1123', 'xml': {'name': 'InsertionTime'}},
        'expiration_time': {'key': 'ExpirationTime', 'type': 'rfc-1123', 'xml': {'name': 'ExpirationTime'}},
        'dequeue_count': {'key': 'DequeueCount', 'type': 'long', 'xml': {'name': 'DequeueCount'}},
        'message_text': {'key': 'MessageText', 'type': 'str', 'xml': {'name': 'MessageText'}},
    }

    _xml_map = {
        'name': 'QueueMessage'
    }

    def __init__(self, **kwargs):
        super(PeekedMessageItem, self).__init__(**kwargs)
        self.message_id = kwargs.get('message_id', None)
        self.insertion_time = kwargs.get('insertion_time', None)
        self.expiration_time = kwargs.get('expiration_time', None)
        self.dequeue_count = kwargs.get('dequeue_count', None)
        self.message_text = kwargs.get('message_text', None)


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
        'name': {'key': 'Name', 'type': 'str', 'xml': {'name': 'Name'}},
        'metadata': {'key': 'Metadata', 'type': '{str}', 'xml': {'name': 'Metadata'}},
    }

    def __init__(self, **kwargs):
        super(QueueItem, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.metadata = kwargs.get('metadata', None)


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
        'message_text': {'key': 'MessageText', 'type': 'str', 'xml': {'name': 'MessageText'}},
    }

    _xml_map = {
        'name': 'QueueMessage'
    }

    def __init__(self, **kwargs):
        super(QueueMessage, self).__init__(**kwargs)
        self.message_text = kwargs.get('message_text', None)


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
        'enabled': {'key': 'Enabled', 'type': 'bool', 'xml': {'name': 'Enabled'}},
        'days': {'key': 'Days', 'type': 'int', 'xml': {'name': 'Days'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(RetentionPolicy, self).__init__(**kwargs)
        self.enabled = kwargs.get('enabled', None)
        self.days = kwargs.get('days', None)


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
        'id': {'key': 'Id', 'type': 'str', 'xml': {'name': 'Id'}},
        'access_policy': {'key': 'AccessPolicy', 'type': 'AccessPolicy', 'xml': {'name': 'AccessPolicy'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(SignedIdentifier, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.access_policy = kwargs.get('access_policy', None)


class StorageError(Model):
    """StorageError.

    :param message:
    :type message: str
    """

    _attribute_map = {
        'message': {'key': 'Message', 'type': 'str', 'xml': {'name': 'Message'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(StorageError, self).__init__(**kwargs)
        self.message = kwargs.get('message', None)


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
        'logging': {'key': 'Logging', 'type': 'Logging', 'xml': {'name': 'Logging'}},
        'hour_metrics': {'key': 'HourMetrics', 'type': 'Metrics', 'xml': {'name': 'HourMetrics'}},
        'minute_metrics': {'key': 'MinuteMetrics', 'type': 'Metrics', 'xml': {'name': 'MinuteMetrics'}},
        'cors': {'key': 'Cors', 'type': '[CorsRule]', 'xml': {'name': 'Cors', 'itemsName': 'CorsRule', 'wrapped': True}},
        'default_service_version': {'key': 'DefaultServiceVersion', 'type': 'str', 'xml': {'name': 'DefaultServiceVersion'}},
        'delete_retention_policy': {'key': 'DeleteRetentionPolicy', 'type': 'RetentionPolicy', 'xml': {'name': 'DeleteRetentionPolicy'}},
        'static_website': {'key': 'StaticWebsite', 'type': 'StaticWebsite', 'xml': {'name': 'StaticWebsite'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(StorageServiceProperties, self).__init__(**kwargs)
        self.logging = kwargs.get('logging', None)
        self.hour_metrics = kwargs.get('hour_metrics', None)
        self.minute_metrics = kwargs.get('minute_metrics', None)
        self.cors = kwargs.get('cors', None)


class StorageServiceStats(Model):
    """Stats for the storage service.

    :param geo_replication: Geo-Replication information for the Secondary
     Storage Service
    :type geo_replication: ~queue.models.GeoReplication
    """

    _attribute_map = {
        'geo_replication': {'key': 'GeoReplication', 'type': 'GeoReplication', 'xml': {'name': 'GeoReplication'}},
    }
    _xml_map = {
    }

    def __init__(self, **kwargs):
        super(StorageServiceStats, self).__init__(**kwargs)
        self.geo_replication = kwargs.get('geo_replication', None)
