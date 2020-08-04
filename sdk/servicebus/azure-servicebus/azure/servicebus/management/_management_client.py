# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
# pylint:disable=protected-access
# pylint:disable=specify-parameter-names-in-call
import functools
from typing import TYPE_CHECKING, Dict, Any, Union, cast
from xml.etree.ElementTree import ElementTree

from azure.core.paging import ItemPaged
from azure.core.exceptions import ResourceNotFoundError
from azure.core.pipeline import Pipeline
from azure.core.pipeline.policies import HttpLoggingPolicy, DistributedTracingPolicy, ContentDecodePolicy, \
    RequestIdPolicy, BearerTokenCredentialPolicy
from azure.core.pipeline.transport import RequestsTransport

from ._generated.models import QueueDescriptionFeed, TopicDescriptionEntry, \
    QueueDescriptionEntry, SubscriptionDescriptionFeed, SubscriptionDescriptionEntry, RuleDescriptionEntry, \
    RuleDescriptionFeed, NamespacePropertiesEntry, CreateTopicBody, CreateTopicBodyContent, \
    TopicDescriptionFeed, CreateSubscriptionBody, CreateSubscriptionBodyContent, CreateRuleBody, \
    CreateRuleBodyContent, CreateQueueBody, CreateQueueBodyContent, NamespaceProperties
from ._utils import extract_data_template, get_next_template, deserialize_rule_key_values, serialize_rule_key_values, \
    extract_rule_data_template
from ._xml_workaround_policy import ServiceBusXMLWorkaroundPolicy

from .._common.constants import JWT_TOKEN_SCOPE
from .._common.utils import parse_conn_str
from .._base_handler import ServiceBusSharedKeyCredential
from ._shared_key_policy import ServiceBusSharedKeyCredentialPolicy
from ._generated._configuration import ServiceBusManagementClientConfiguration
from ._generated._service_bus_management_client import ServiceBusManagementClient as ServiceBusManagementClientImpl
from ._model_workaround import avoid_timedelta_overflow
from . import _constants as constants
from ._models import QueueRuntimeProperties, QueueProperties, TopicProperties, TopicRuntimeProperties, \
    SubscriptionProperties, SubscriptionRuntimeProperties, RuleProperties
from ._handle_response_error import _handle_response_error

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential  # pylint:disable=ungrouped-imports


class ServiceBusManagementClient:  # pylint:disable=too-many-public-methods
    """Use this client to create, update, list, and delete resources of a ServiceBus namespace.

    :param str fully_qualified_namespace: The fully qualified host name for the Service Bus namespace.
    :param credential: To authenticate to manage the entities of the ServiceBus namespace.
    :type credential: Union[TokenCredential, azure.servicebus.ServiceBusSharedKeyCredential]
    """

    def __init__(self, fully_qualified_namespace, credential, **kwargs):
        # type: (str, Union[TokenCredential, ServiceBusSharedKeyCredential], Dict[str, Any]) -> None
        self.fully_qualified_namespace = fully_qualified_namespace
        self._credential = credential
        self._endpoint = "https://" + fully_qualified_namespace
        self._config = ServiceBusManagementClientConfiguration(self._endpoint, **kwargs)
        self._pipeline = self._build_pipeline()
        self._impl = ServiceBusManagementClientImpl(endpoint=fully_qualified_namespace, pipeline=self._pipeline)

    def __enter__(self):
        self._impl.__enter__()
        return self

    def __exit__(self, *exc_details):
        self._impl.__exit__(*exc_details)

    def _build_pipeline(self, **kwargs):  # pylint: disable=no-self-use
        transport = kwargs.get('transport')
        policies = kwargs.get('policies')
        credential_policy = ServiceBusSharedKeyCredentialPolicy(self._endpoint, self._credential, "Authorization") \
            if isinstance(self._credential, ServiceBusSharedKeyCredential) \
            else BearerTokenCredentialPolicy(self._credential, JWT_TOKEN_SCOPE)
        if policies is None:  # [] is a valid policy list
            policies = [
                RequestIdPolicy(**kwargs),
                self._config.headers_policy,
                self._config.user_agent_policy,
                self._config.proxy_policy,
                ContentDecodePolicy(**kwargs),
                ServiceBusXMLWorkaroundPolicy(),
                self._config.redirect_policy,
                self._config.retry_policy,
                credential_policy,
                self._config.logging_policy,
                DistributedTracingPolicy(**kwargs),
                HttpLoggingPolicy(**kwargs),
            ]
        if not transport:
            transport = RequestsTransport(**kwargs)
        return Pipeline(transport, policies)

    def _get_entity_element(self, entity_name, enrich=False, **kwargs):
        # type: (str, bool, Any) -> ElementTree

        with _handle_response_error():
            element = cast(
                ElementTree,
                self._impl.entity.get(entity_name, enrich=enrich, api_version=constants.API_VERSION, **kwargs)
            )
        return element

    def _get_subscription_element(self, topic_name, subscription_name, enrich=False, **kwargs):
        # type: (str, str, bool, Any) -> ElementTree

        with _handle_response_error():
            element = cast(
                ElementTree,
                self._impl.subscription.get(
                    topic_name, subscription_name, enrich=enrich, api_version=constants.API_VERSION, **kwargs)
            )
        return element

    def _get_rule_element(self, topic_name, subscription_name, rule_name, **kwargs):
        # type: (str, str, str, Any) -> ElementTree

        with _handle_response_error():
            element = cast(
                ElementTree,
                self._impl.rule.get(
                    topic_name, subscription_name, rule_name, enrich=False, api_version=constants.API_VERSION, **kwargs)
            )
        return element

    @classmethod
    def from_connection_string(cls, conn_str, **kwargs):
        # type: (str, Any) -> ServiceBusManagementClient
        """Create a client from connection string.

        :param str conn_str: The connection string of the Service Bus Namespace.
        :rtype: ~azure.servicebus.management.ServiceBusManagementClient
        """
        endpoint, shared_access_key_name, shared_access_key, _ = parse_conn_str(conn_str)
        if "//" in endpoint:
            endpoint = endpoint[endpoint.index("//") + 2:]
        return cls(endpoint, ServiceBusSharedKeyCredential(shared_access_key_name, shared_access_key), **kwargs)

    def get_queue(self, queue_name, **kwargs):
        # type: (str, Any) -> QueueProperties
        """Get the properties of a queue.

        :param str queue_name: The name of the queue.
        :rtype: ~azure.servicebus.management.QueueProperties
        """
        entry_ele = self._get_entity_element(queue_name, **kwargs)
        entry = QueueDescriptionEntry.deserialize(entry_ele)
        if not entry.content:
            raise ResourceNotFoundError("Queue '{}' does not exist".format(queue_name))
        queue_description = QueueProperties._from_internal_entity(queue_name, entry.content.queue_description)
        return queue_description

    def get_queue_runtime_info(self, queue_name, **kwargs):
        # type: (str, Any) -> QueueRuntimeProperties
        """Get the runtime information of a queue.

        :param str queue_name: The name of the queue.
        :rtype: ~azure.servicebus.management.QueueRuntimeProperties
        """
        entry_ele = self._get_entity_element(queue_name, **kwargs)
        entry = QueueDescriptionEntry.deserialize(entry_ele)
        if not entry.content:
            raise ResourceNotFoundError("Queue {} does not exist".format(queue_name))
        runtime_info = QueueRuntimeProperties._from_internal_entity(queue_name, entry.content.queue_description)
        return runtime_info

    def create_queue(self, name, **kwargs):
        # type: (str, Any) -> QueueProperties
        """Create a queue.

        :param name: Name of the queue.
        :type name: str
        :keyword authorization_rules: Authorization rules for resource.
        :type authorization_rules: list[~azure.servicebus.management.AuthorizationRule]
        :keyword auto_delete_on_idle: ISO 8601 timeSpan idle interval after which the queue is
         automatically deleted. The minimum duration is 5 minutes.
        :type auto_delete_on_idle: ~datetime.timedelta
        :keyword dead_lettering_on_message_expiration: A value that indicates whether this queue has dead
         letter support when a message expires.
        :type dead_lettering_on_message_expiration: bool
        :keyword default_message_time_to_live: ISO 8601 default message timespan to live value. This is
         the duration after which the message expires, starting from when the message is sent to Service
         Bus. This is the default value used when TimeToLive is not set on a message itself.
        :type default_message_time_to_live: ~datetime.timedelta
        :keyword duplicate_detection_history_time_window: ISO 8601 timeSpan structure that defines the
         duration of the duplicate detection history. The default value is 10 minutes.
        :type duplicate_detection_history_time_window: ~datetime.timedelta
        :keyword enable_batched_operations: Value that indicates whether server-side batched operations
         are enabled.
        :type enable_batched_operations: bool
        :keyword enable_express: A value that indicates whether Express Entities are enabled. An express
         queue holds a message in memory temporarily before writing it to persistent storage.
        :type enable_express: bool
        :keyword enable_partitioning: A value that indicates whether the queue is to be partitioned
         across multiple message brokers.
        :type enable_partitioning: bool
        :keyword is_anonymous_accessible: A value indicating if the resource can be accessed without
         authorization.
        :type is_anonymous_accessible: bool
        :keyword lock_duration: ISO 8601 timespan duration of a peek-lock; that is, the amount of time
         that the message is locked for other receivers. The maximum value for LockDuration is 5
         minutes; the default value is 1 minute.
        :type lock_duration: ~datetime.timedelta
        :keyword max_delivery_count: The maximum delivery count. A message is automatically deadlettered
         after this number of deliveries. Default value is 10.
        :type max_delivery_count: int
        :keyword max_size_in_megabytes: The maximum size of the queue in megabytes, which is the size of
         memory allocated for the queue.
        :type max_size_in_megabytes: int
        :keyword requires_duplicate_detection: A value indicating if this queue requires duplicate
         detection.
        :type requires_duplicate_detection: bool
        :keyword requires_session: A value that indicates whether the queue supports the concept of
         sessions.
        :type requires_session: bool
        :keyword forward_to: The name of the recipient entity to which all the messages sent to the queue
         are forwarded to.
        :type forward_to: str
        :keyword user_metadata: Custom metdata that user can associate with the description. Max length
         is 1024 chars.
        :type user_metadata: str
        :keyword support_ordering: A value that indicates whether the queue supports ordering.
        :type support_ordering: bool
        :keyword forward_dead_lettered_messages_to: The name of the recipient entity to which all the
         dead-lettered messages of this subscription are forwarded to.
        :type forward_dead_lettered_messages_to: str

        :rtype: ~azure.servicebus.management.QueueProperties
        """
        queue = QueueProperties(name, **kwargs)
        for key in queue.keys():
            kwargs.pop(key, None)
        to_create = queue._to_internal_entity()
        create_entity_body = CreateQueueBody(
            content=CreateQueueBodyContent(
                queue_description=to_create,  # type: ignore
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        with _handle_response_error():
            entry_ele = cast(
                ElementTree,
                self._impl.entity.put(
                    name,  # type: ignore
                    request_body, api_version=constants.API_VERSION, **kwargs)
            )

        entry = QueueDescriptionEntry.deserialize(entry_ele)
        result = QueueProperties._from_internal_entity(name, entry.content.queue_description)
        return result

    def update_queue(self, queue, **kwargs):
        # type: (QueueProperties, Any) -> None
        """Update a queue.

        Before calling this method, you should use `get_queue` to get a `QueueProperties` instance, then update
        the properties you want to update. Only a portion of properties can be updated.
        Refer to https://docs.microsoft.com/en-us/rest/api/servicebus/update-queue.

        :param queue: The queue that is returned from `get_queue` and has the updated properties.
        :type queue: ~azure.servicebus.management.QueueProperties
        :rtype: None
        """

        to_update = queue._to_internal_entity()

        to_update.default_message_time_to_live = avoid_timedelta_overflow(to_update.default_message_time_to_live)
        to_update.auto_delete_on_idle = avoid_timedelta_overflow(to_update.auto_delete_on_idle)

        create_entity_body = CreateQueueBody(
            content=CreateQueueBodyContent(
                queue_description=to_update,
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        with _handle_response_error():
            self._impl.entity.put(
                queue.name,  # type: ignore
                request_body,
                api_version=constants.API_VERSION,
                if_match="*",
                **kwargs
            )

    def delete_queue(self, queue, **kwargs):
        # type: (Union[str, QueueProperties], Any) -> None
        """Delete a queue.

        :param Union[str, azure.servicebus.management.QueueProperties] queue: The name of the queue or
         a `QueueProperties` with name.
        :rtype: None
        """
        try:
            queue_name = queue.name  # type: ignore
        except AttributeError:
            queue_name = queue
        if not queue_name:
            raise ValueError("queue_name must not be None or empty")
        with _handle_response_error():
            self._impl.entity.delete(
                queue_name,   # type: ignore
                api_version=constants.API_VERSION, **kwargs)

    def list_queues(self, **kwargs):
        # type: (Any) -> ItemPaged[QueueProperties]
        """List the queues of a ServiceBus namespace.

        :returns: An iterable (auto-paging) response of QueueProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.servicebus.management.QueueProperties]
        """

        def entry_to_qd(entry):
            qd = QueueProperties._from_internal_entity(entry.title, entry.content.queue_description)
            return qd

        extract_data = functools.partial(
            extract_data_template, QueueDescriptionFeed, entry_to_qd
        )
        get_next = functools.partial(
            get_next_template, functools.partial(self._impl.list_entities, constants.ENTITY_TYPE_QUEUES), **kwargs
        )
        return ItemPaged(
            get_next, extract_data)

    def list_queues_runtime_info(self, **kwargs):
        # type: (Any) -> ItemPaged[QueueRuntimeProperties]
        """List the runtime information of the queues in a ServiceBus namespace.

        :returns: An iterable (auto-paging) response of QueueRuntimeProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.servicebus.management.QueueRuntimeProperties]
        """

        def entry_to_qr(entry):
            qd = QueueRuntimeProperties._from_internal_entity(entry.title, entry.content.queue_description)
            return qd

        extract_data = functools.partial(
            extract_data_template, QueueDescriptionFeed, entry_to_qr
        )
        get_next = functools.partial(
            get_next_template, functools.partial(self._impl.list_entities, constants.ENTITY_TYPE_QUEUES), **kwargs
        )
        return ItemPaged(
            get_next, extract_data)

    def get_topic(self, topic_name, **kwargs):
        # type: (str, Any) -> TopicProperties
        """Get the properties of a topic.

        :param str topic_name: The name of the topic.
        :rtype: ~azure.servicebus.management.TopicProperties
        """
        entry_ele = self._get_entity_element(topic_name, **kwargs)
        entry = TopicDescriptionEntry.deserialize(entry_ele)
        if not entry.content:
            raise ResourceNotFoundError("Topic '{}' does not exist".format(topic_name))
        topic_description = TopicProperties._from_internal_entity(topic_name, entry.content.topic_description)
        return topic_description

    def get_topic_runtime_info(self, topic_name, **kwargs):
        # type: (str, Any) -> TopicRuntimeProperties
        """Get a the runtime information of a topic.

        :param str topic_name: The name of the topic.
        :rtype: ~azure.servicebus.management.TopicRuntimeProperties
        """
        entry_ele = self._get_entity_element(topic_name, **kwargs)
        entry = TopicDescriptionEntry.deserialize(entry_ele)
        if not entry.content:
            raise ResourceNotFoundError("Topic {} does not exist".format(topic_name))
        topic_description = TopicRuntimeProperties._from_internal_entity(topic_name, entry.content.topic_description)
        return topic_description

    def create_topic(self, name, **kwargs):
        # type: (str, Any) -> TopicProperties
        """Create a topic.

        :param name: Name of the topic.
        :type name: str
        :keyword default_message_time_to_live: ISO 8601 default message timespan to live value. This is
         the duration after which the message expires, starting from when the message is sent to Service
         Bus. This is the default value used when TimeToLive is not set on a message itself.
        :type default_message_time_to_live: ~datetime.timedelta
        :keyword max_size_in_megabytes: The maximum size of the topic in megabytes, which is the size of
         memory allocated for the topic.
        :type max_size_in_megabytes: long
        :keyword requires_duplicate_detection: A value indicating if this topic requires duplicate
         detection.
        :type requires_duplicate_detection: bool
        :keyword duplicate_detection_history_time_window: ISO 8601 timeSpan structure that defines the
         duration of the duplicate detection history. The default value is 10 minutes.
        :type duplicate_detection_history_time_window: ~datetime.timedelta
        :keyword enable_batched_operations: Value that indicates whether server-side batched operations
         are enabled.
        :type enable_batched_operations: bool
        :keyword size_in_bytes: The size of the topic, in bytes.
        :type size_in_bytes: int
        :keyword filtering_messages_before_publishing: Filter messages before publishing.
        :type filtering_messages_before_publishing: bool
        :keyword is_anonymous_accessible: A value indicating if the resource can be accessed without
         authorization.
        :type is_anonymous_accessible: bool
        :keyword authorization_rules: Authorization rules for resource.
        :type authorization_rules:
         list[~azure.servicebus.management.AuthorizationRule]
        :keyword support_ordering: A value that indicates whether the topic supports ordering.
        :type support_ordering: bool
        :keyword auto_delete_on_idle: ISO 8601 timeSpan idle interval after which the topic is
         automatically deleted. The minimum duration is 5 minutes.
        :type auto_delete_on_idle: ~datetime.timedelta
        :keyword enable_partitioning: A value that indicates whether the topic is to be partitioned
         across multiple message brokers.
        :type enable_partitioning: bool
        :keyword enable_subscription_partitioning: A value that indicates whether the topic's
         subscription is to be partitioned.
        :type enable_subscription_partitioning: bool
        :keyword enable_express: A value that indicates whether Express Entities are enabled. An express
         queue holds a message in memory temporarily before writing it to persistent storage.
        :type enable_express: bool
        :keyword user_metadata: Metadata associated with the topic.
        :type user_metadata: str

        :rtype: ~azure.servicebus.management.TopicProperties
        """
        topic = TopicProperties(name, **kwargs)
        for key in topic.keys():
            kwargs.pop(key, None)
        to_create = topic._to_internal_entity()

        create_entity_body = CreateTopicBody(
            content=CreateTopicBodyContent(
                topic_description=to_create,  # type: ignore
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        with _handle_response_error():
            entry_ele = cast(
                ElementTree,
                self._impl.entity.put(
                    name,  # type: ignore
                    request_body, api_version=constants.API_VERSION, **kwargs)
            )
        entry = TopicDescriptionEntry.deserialize(entry_ele)
        result = TopicProperties._from_internal_entity(name, entry.content.topic_description)
        return result

    def update_topic(self, topic, **kwargs):
        # type: (TopicProperties, Any) -> None
        """Update a topic.

        Before calling this method, you should use `get_topic` to get a `TopicProperties` instance, then
        update the properties you want to update. Only a portion of properties can be updated.
        Refer to https://docs.microsoft.com/en-us/rest/api/servicebus/update-topic.

        :param topic: The topic that is returned from `get_topic` and has the updated properties.
        :type topic: ~azure.servicebus.management.TopicProperties
        :rtype: None
        """

        to_update = topic._to_internal_entity()

        to_update.default_message_time_to_live = kwargs.get(
            "default_message_time_to_live") or topic.default_message_time_to_live
        to_update.duplicate_detection_history_time_window = kwargs.get(
            "duplicate_detection_history_time_window") or topic.duplicate_detection_history_time_window

        to_update.default_message_time_to_live = avoid_timedelta_overflow(to_update.default_message_time_to_live)
        to_update.auto_delete_on_idle = avoid_timedelta_overflow(to_update.auto_delete_on_idle)

        create_entity_body = CreateTopicBody(
            content=CreateTopicBodyContent(
                topic_description=to_update,
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        with _handle_response_error():
            self._impl.entity.put(
                topic.name,  # type: ignore
                request_body,
                api_version=constants.API_VERSION,
                if_match="*",
                **kwargs
            )

    def delete_topic(self, topic, **kwargs):
        # type: (Union[str, TopicProperties], Any) -> None
        """Delete a topic.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic to be deleted.
        :rtype: None
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        self._impl.entity.delete(topic_name, api_version=constants.API_VERSION, **kwargs)

    def list_topics(self, **kwargs):
        # type: (Any) -> ItemPaged[TopicProperties]
        """List the topics of a ServiceBus namespace.

        :returns: An iterable (auto-paging) response of TopicProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.servicebus.management.TopicProperties]
        """
        def entry_to_topic(entry):
            topic = TopicProperties._from_internal_entity(entry.title, entry.content.topic_description)
            return topic

        extract_data = functools.partial(
            extract_data_template, TopicDescriptionFeed, entry_to_topic
        )
        get_next = functools.partial(
            get_next_template, functools.partial(self._impl.list_entities, constants.ENTITY_TYPE_TOPICS), **kwargs
        )
        return ItemPaged(
            get_next, extract_data)

    def list_topics_runtime_info(self, **kwargs):
        # type: (Any) -> ItemPaged[TopicRuntimeProperties]
        """List the topics runtime information of a ServiceBus namespace.

        :returns: An iterable (auto-paging) response of TopicRuntimeProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.servicebus.management.TopicRuntimeProperties]
        """
        def entry_to_topic(entry):
            topic = TopicRuntimeProperties._from_internal_entity(entry.title, entry.content.topic_description)
            return topic

        extract_data = functools.partial(
            extract_data_template, TopicDescriptionFeed, entry_to_topic
        )
        get_next = functools.partial(
            get_next_template, functools.partial(self._impl.list_entities, constants.ENTITY_TYPE_TOPICS), **kwargs
        )
        return ItemPaged(
            get_next, extract_data)

    def get_subscription(self, topic, subscription_name, **kwargs):
        # type: (Union[str, TopicProperties], str, Any) -> SubscriptionProperties
        """Get the properties of a topic subscription.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :param str subscription_name: name of the subscription.
        :rtype: ~azure.servicebus.management.SubscriptionProperties
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        entry_ele = self._get_subscription_element(topic_name, subscription_name, **kwargs)
        entry = SubscriptionDescriptionEntry.deserialize(entry_ele)
        if not entry.content:
            raise ResourceNotFoundError(
                "Subscription('Topic: {}, Subscription: {}') does not exist".format(subscription_name, topic_name))
        subscription = SubscriptionProperties._from_internal_entity(
            entry.title, entry.content.subscription_description)
        return subscription

    def get_subscription_runtime_info(self, topic, subscription_name, **kwargs):
        # type: (Union[str, TopicProperties], str, Any) -> SubscriptionRuntimeProperties
        """Get a topic subscription runtime info.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :param str subscription_name: name of the subscription.
        :rtype: ~azure.servicebus.management.SubscriptionRuntimeProperties
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        entry_ele = self._get_subscription_element(topic_name, subscription_name, **kwargs)
        entry = SubscriptionDescriptionEntry.deserialize(entry_ele)
        if not entry.content:
            raise ResourceNotFoundError(
                "Subscription('Topic: {}, Subscription: {}') does not exist".format(subscription_name, topic_name))
        subscription = SubscriptionRuntimeProperties._from_internal_entity(
            entry.title, entry.content.subscription_description)
        return subscription

    def create_subscription(self, topic, name, **kwargs):
        # type: (Union[str, TopicProperties], str, Any) -> SubscriptionProperties
        """Create a topic subscription.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that will own the
         to-be-created subscription.
        :param name: Name of the subscription.
        :type name: str
        :keyword lock_duration: ISO 8601 timespan duration of a peek-lock; that is, the amount of time
         that the message is locked for other receivers. The maximum value for LockDuration is 5
         minutes; the default value is 1 minute.
        :type lock_duration: ~datetime.timedelta
        :keyword requires_session: A value that indicates whether the queue supports the concept of
         sessions.
        :type requires_session: bool
        :keyword default_message_time_to_live: ISO 8601 default message timespan to live value. This is
         the duration after which the message expires, starting from when the message is sent to Service
         Bus. This is the default value used when TimeToLive is not set on a message itself.
        :type default_message_time_to_live: ~datetime.timedelta
        :keyword dead_lettering_on_message_expiration: A value that indicates whether this subscription
         has dead letter support when a message expires.
        :type dead_lettering_on_message_expiration: bool
        :keyword dead_lettering_on_filter_evaluation_exceptions: A value that indicates whether this
         subscription has dead letter support when a message expires.
        :type dead_lettering_on_filter_evaluation_exceptions: bool
        :keyword max_delivery_count: The maximum delivery count. A message is automatically deadlettered
         after this number of deliveries. Default value is 10.
        :type max_delivery_count: int
        :keyword enable_batched_operations: Value that indicates whether server-side batched operations
         are enabled.
        :type enable_batched_operations: bool
        :keyword forward_to: The name of the recipient entity to which all the messages sent to the
         subscription are forwarded to.
        :type forward_to: str
        :keyword user_metadata: Metadata associated with the subscription. Maximum number of characters
         is 1024.
        :type user_metadata: str
        :keyword forward_dead_lettered_messages_to: The name of the recipient entity to which all the
         messages sent to the subscription are forwarded to.
        :type forward_dead_lettered_messages_to: str
        :keyword auto_delete_on_idle: ISO 8601 timeSpan idle interval after which the subscription is
         automatically deleted. The minimum duration is 5 minutes.
        :type auto_delete_on_idle: ~datetime.timedelta
        :rtype:  ~azure.servicebus.management.SubscriptionProperties
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        subscription = SubscriptionProperties(name, **kwargs)
        for key in subscription.keys():
            kwargs.pop(key, None)
        to_create = subscription._to_internal_entity()  # type: ignore  # pylint:disable=protected-access

        create_entity_body = CreateSubscriptionBody(
            content=CreateSubscriptionBodyContent(
                subscription_description=to_create,  # type: ignore
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        with _handle_response_error():
            entry_ele = cast(
                ElementTree,
                self._impl.subscription.put(
                    topic_name,
                    name,  # type: ignore
                    request_body, api_version=constants.API_VERSION, **kwargs)
            )

        entry = SubscriptionDescriptionEntry.deserialize(entry_ele)
        result = SubscriptionProperties._from_internal_entity(
            name, entry.content.subscription_description)
        return result

    def update_subscription(self, topic, subscription, **kwargs):
        # type: (Union[str, TopicProperties], SubscriptionProperties, Any) -> None
        """Update a subscription.

        Before calling this method, you should use `get_subscription` to get a `SubscriptionProperties` instance,
        then update the properties you want to update.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :param ~azure.servicebus.management.SubscriptionProperties subscription: The subscription that is returned
         from `get_subscription` and has the updated properties.
        :rtype: None
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic

        to_update = subscription._to_internal_entity()

        to_update.default_message_time_to_live = avoid_timedelta_overflow(to_update.default_message_time_to_live)
        to_update.auto_delete_on_idle = avoid_timedelta_overflow(to_update.auto_delete_on_idle)

        create_entity_body = CreateSubscriptionBody(
            content=CreateSubscriptionBodyContent(
                subscription_description=to_update,
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        with _handle_response_error():
            self._impl.subscription.put(
                topic_name,
                subscription.name,
                request_body,
                api_version=constants.API_VERSION,
                if_match="*",
                **kwargs
            )

    def delete_subscription(self, topic, subscription, **kwargs):
        # type: (Union[str, TopicProperties], Union[str, SubscriptionProperties], Any) -> None
        """Delete a topic subscription.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :param Union[str, ~azure.servicebus.management.SubscriptionProperties] subscription: The subscription to
         be deleted.
        :rtype: None
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        try:
            subscription_name = subscription.name  # type: ignore
        except AttributeError:
            subscription_name = subscription
        self._impl.subscription.delete(topic_name, subscription_name, api_version=constants.API_VERSION, **kwargs)

    def list_subscriptions(self, topic, **kwargs):
        # type: (Union[str, TopicProperties], Any) -> ItemPaged[SubscriptionProperties]
        """List the subscriptions of a ServiceBus Topic.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :returns: An iterable (auto-paging) response of SubscriptionProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.servicebus.management.SubscriptionProperties]
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic

        def entry_to_subscription(entry):
            subscription = SubscriptionProperties._from_internal_entity(
                entry.title, entry.content.subscription_description)
            return subscription

        extract_data = functools.partial(
            extract_data_template, SubscriptionDescriptionFeed, entry_to_subscription
        )
        get_next = functools.partial(
            get_next_template, functools.partial(self._impl.list_subscriptions, topic_name), **kwargs
        )
        return ItemPaged(
            get_next, extract_data)

    def list_subscriptions_runtime_info(self, topic, **kwargs):
        # type: (Union[str, TopicProperties], Any) -> ItemPaged[SubscriptionRuntimeProperties]
        """List the subscriptions runtime information of a ServiceBus Topic.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :returns: An iterable (auto-paging) response of SubscriptionRuntimeProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.servicebus.management.SubscriptionRuntimeProperties]
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic

        def entry_to_subscription(entry):
            subscription = SubscriptionRuntimeProperties._from_internal_entity(
                entry.title, entry.content.subscription_description)
            return subscription

        extract_data = functools.partial(
            extract_data_template, SubscriptionDescriptionFeed, entry_to_subscription
        )
        get_next = functools.partial(
            get_next_template, functools.partial(self._impl.list_subscriptions, topic_name), **kwargs
        )
        return ItemPaged(
            get_next, extract_data)

    def get_rule(self, topic, subscription, rule_name, **kwargs):
        # type: (Union[str, TopicProperties], Union[str, SubscriptionProperties], str, Any) -> RuleProperties
        """Get the properties of a topic subscription rule.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :param Union[str, ~azure.servicebus.management.SubscriptionProperties] subscription: The subscription that
         owns the rule.
        :param str rule_name: Name of the rule.
        :rtype: ~azure.servicebus.management.RuleProperties
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        try:
            subscription_name = subscription.name  # type: ignore
        except AttributeError:
            subscription_name = subscription
        entry_ele = self._get_rule_element(topic_name, subscription_name, rule_name, **kwargs)
        entry = RuleDescriptionEntry.deserialize(entry_ele)
        if not entry.content:
            raise ResourceNotFoundError(
                "Rule('Topic: {}, Subscription: {}, Rule {}') does not exist".format(
                    subscription_name, topic_name, rule_name))
        rule_description = RuleProperties._from_internal_entity(rule_name, entry.content.rule_description)
        deserialize_rule_key_values(entry_ele, rule_description)  # to remove after #3535 is released.
        return rule_description

    def create_rule(self, topic, subscription, name, **kwargs):
        # type: (Union[str, TopicProperties], Union[str, SubscriptionProperties], str, Any) -> RuleProperties
        """Create a rule for a topic subscription.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that will own the
         to-be-created subscription rule.
        :param Union[str, ~azure.servicebus.management.SubscriptionProperties] subscription: The subscription that
         will own the to-be-created rule.
        :param name: Name of the rule.
        :type name: str
        :keyword filter: The filter of the rule.
        :type filter: Union[~azure.servicebus.management.CorrelationRuleFilter,
         ~azure.servicebus.management.SqlRuleFilter]
        :keyword action: The action of the rule.
        :type action: Optional[~azure.servicebus.management.SqlRuleAction]
        :keyword created_at: The exact time the rule was created.
        :type created_at: ~datetime.datetime

        :rtype: ~azure.servicebus.management.RuleProperties
        """

        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        try:
            subscription_name = subscription.name  # type: ignore
        except AttributeError:
            subscription_name = subscription
        rule = RuleProperties(name, **kwargs)
        for key in rule.keys():
            kwargs.pop(key, None)
        to_create = rule._to_internal_entity()

        create_entity_body = CreateRuleBody(
            content=CreateRuleBodyContent(
                rule_description=to_create,  # type: ignore
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        serialize_rule_key_values(request_body, rule)
        with _handle_response_error():
            entry_ele = self._impl.rule.put(
                topic_name,
                subscription_name,  # type: ignore
                name,
                request_body, api_version=constants.API_VERSION, **kwargs)
        entry = RuleDescriptionEntry.deserialize(entry_ele)
        result = RuleProperties._from_internal_entity(name, entry.content.rule_description)
        deserialize_rule_key_values(entry_ele, result)  # to remove after #3535 is released.
        return result

    def update_rule(self, topic, subscription, rule, **kwargs):
        # type: (Union[str, TopicProperties], Union[str, SubscriptionProperties], RuleProperties, Any) -> None
        """Update a rule.

        Before calling this method, you should use `get_rule` to get a `RuleProperties` instance,
        then update the properties you want to update.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :param Union[str, ~azure.servicebus.management.SubscriptionProperties] subscription: The subscription that
         owns this rule.
        :param ~azure.servicebus.management.RuleProperties rule: The rule that is returned
         from `get_rule` and has the updated properties.
        :rtype: None
        """

        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        try:
            subscription_name = subscription.name  # type: ignore
        except AttributeError:
            subscription_name = subscription

        to_update = rule._to_internal_entity()

        create_entity_body = CreateRuleBody(
            content=CreateRuleBodyContent(
                rule_description=to_update,
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        serialize_rule_key_values(request_body, rule)
        with _handle_response_error():
            self._impl.rule.put(
                topic_name,
                subscription_name,
                rule.name,
                request_body,
                api_version=constants.API_VERSION,
                if_match="*",
                **kwargs
            )

    def delete_rule(self, topic, subscription, rule, **kwargs):
        # type: (Union[str, TopicProperties], Union[str, SubscriptionProperties], Union[str, RuleProperties], Any) -> None  # pylint:disable=line-too-long
        """Delete a topic subscription rule.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :param Union[str, ~azure.servicebus.management.SubscriptionProperties] subscription: The subscription that
         owns the topic.
        :param Union[str, ~azure.servicebus.management.RuleProperties] rule: The to-be-deleted rule.
        :rtype: None
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        try:
            subscription_name = subscription.name  # type: ignore
        except AttributeError:
            subscription_name = subscription
        try:
            rule_name = rule.name  # type: ignore
        except AttributeError:
            rule_name = rule
        self._impl.rule.delete(topic_name, subscription_name, rule_name, api_version=constants.API_VERSION, **kwargs)

    def list_rules(self, topic, subscription, **kwargs):
        # type: (Union[str, TopicProperties], Union[str, SubscriptionProperties], Any) -> ItemPaged[RuleProperties]
        """List the rules of a topic subscription.

        :param Union[str, ~azure.servicebus.management.TopicProperties] topic: The topic that owns the subscription.
        :param Union[str, ~azure.servicebus.management.SubscriptionProperties] subscription: The subscription that
         owns the rules.
        :returns: An iterable (auto-paging) response of RuleProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.servicebus.management.RuleProperties]
        """
        try:
            topic_name = topic.name  # type: ignore
        except AttributeError:
            topic_name = topic
        try:
            subscription_name = subscription.name  # type: ignore
        except AttributeError:
            subscription_name = subscription

        def entry_to_rule(ele, entry):
            """
            `ele` will be removed after https://github.com/Azure/autorest/issues/3535 is released.
            """
            rule = entry.content.rule_description
            rule_description = RuleProperties._from_internal_entity(entry.title, rule)
            deserialize_rule_key_values(ele, rule_description)  # to remove after #3535 is released.
            return rule_description

        extract_data = functools.partial(
            extract_rule_data_template, RuleDescriptionFeed, entry_to_rule
        )
        get_next = functools.partial(
            get_next_template, functools.partial(self._impl.list_rules, topic_name, subscription_name), **kwargs
        )
        return ItemPaged(
            get_next, extract_data)

    def get_namespace_properties(self, **kwargs):
        # type: (Any) -> NamespaceProperties
        """Get the namespace properties

        :rtype: ~azure.servicebus.management.NamespaceProperties
        """
        entry_el = self._impl.namespace.get(api_version=constants.API_VERSION, **kwargs)
        namespace_entry = NamespacePropertiesEntry.deserialize(entry_el)
        return namespace_entry.content.namespace_properties

    def close(self):
        # type: () -> None
        self._impl.close()
