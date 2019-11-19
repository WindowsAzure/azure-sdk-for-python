# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import logging
import threading
from typing import Any, Union, Dict, Tuple, TYPE_CHECKING, Callable, List

from ._common import EventHubSharedKeyCredential, EventHubSASTokenCredential, EventData
from ._client_base import ClientBase
from ._consumer import EventHubConsumer
from ._constants import ALL_PARTITIONS
from ._eventprocessor.event_processor import EventProcessor
from ._eventprocessor.partition_context import PartitionContext

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential  # type: ignore

_LOGGER = logging.getLogger(__name__)


class EventHubConsumerClient(ClientBase):
    """ The EventHubProducerClient class defines a high level interface for
    receiving events from the Azure Event Hubs service.

    The main goal of `EventHubConsumerClient` is to receive events from all partitions of an EventHub with
    load balancing and checkpointing.

    When multiple `EventHubConsumerClient` works with one process, multiple processes, or multiple computer machines
    and if they use the same repository as the load balancing and checkpointing store, they will balance automatically.
    To enable the load balancing and / or checkpointing, partition_manager must be set when creating the
    `EventHubConsumerClient`.

    An `EventHubConsumerClient` can also receive from a specific partition when you call its method `receive()`
    and specify the partition_id.
    Load balancing won't work in single-partition mode. But users can still save checkpoint if the partition_manager
    is set.

    :param str fully_qualified_namespace: The fully qualified host name for the Event Hubs namespace.
     This is likely to be similar to <yournamespace>.servicebus.windows.net
    :param str eventhub_name: The path of the specific Event Hub to connect the client to.
    :param str consumer_group: Receive events from the event hub for this consumer group.
    :param credential: The credential object used for authentication which implements particular interface
     of getting tokens. It accepts :class:`EventHubSharedKeyCredential<azure.eventhub.EventHubSharedKeyCredential>`,
     :class:`EventHubSASTokenCredential<azure.eventhub.EventHubSASTokenCredential>`, or credential objects generated by
     the azure-identity library and objects that implement `get_token(self, *scopes)` method.
    :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
    :keyword float auth_timeout: The time in seconds to wait for a token to be authorized by the service.
     The default value is 60 seconds. If set to 0, no timeout will be enforced from the client.
    :keyword str user_agent: The user agent that needs to be appended to the built in user agent string.
    :keyword int retry_total: The total number of attempts to redo the failed operation when an error happened. Default
     value is 3.
    :keyword transport_type: The type of transport protocol that will be used for communicating with
     the Event Hubs service. Default is `TransportType.Amqp`.
    :paramtype transport_type: ~azure.eventhub.TransportType
    :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
     keys: 'proxy_hostname' (str value) and 'proxy_port' (int value).
     Additionally the following keys may also be present: 'username', 'password'.
    :keyword partition_manager: stores the load balancing data and checkpoint data when receiving events
     if partition_manager is specified. If it's None, this `EventHubConsumerClient` instance will receive
     events without load balancing and checkpoint.
    :paramtype partition_manager: ~azure.eventhub.PartitionManager
    :keyword float load_balancing_interval: When load balancing kicks in, this is the interval in seconds
     between two load balancing. Default is 10.

    .. admonition:: Example:

        .. literalinclude:: ../samples/sync_samples/sample_code_eventhub.py
            :start-after: [START create_eventhub_consumer_client_sync]
            :end-before: [END create_eventhub_consumer_client_sync]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the EventHubConsumerClient.
    """

    def __init__(self,
                 fully_qualified_namespace,  # type: str
                 eventhub_name,  # type: str
                 consumer_group,  # type: str
                 credential,  # type: Union[EventHubSharedKeyCredential, EventHubSASTokenCredential, TokenCredential]
                 **kwargs
                 ):
        self._partition_manager = kwargs.pop("partition_manager", None)
        self._load_balancing_interval = kwargs.pop("load_balancing_interval", 10)
        self._consumer_group = consumer_group
        network_tracing = kwargs.pop("logging_enable", False)
        super(EventHubConsumerClient, self).__init__(
            fully_qualified_namespace=fully_qualified_namespace,
            eventhub_name=eventhub_name, credential=credential,
            network_tracing=network_tracing, **kwargs)
        self._lock = threading.Lock()
        self._event_processors = {}  # type: Dict[Tuple[str, str], EventProcessor]

    def _create_consumer(self, consumer_group, partition_id, event_position, **kwargs):
        owner_level = kwargs.get("owner_level")
        prefetch = kwargs.get("prefetch") or self._config.prefetch
        track_last_enqueued_event_properties = kwargs.get("track_last_enqueued_event_properties", False)
        on_event_received = kwargs.get("on_event_received")

        source_url = "amqps://{}{}/ConsumerGroups/{}/Partitions/{}".format(
            self._address.hostname, self._address.path, consumer_group, partition_id)
        handler = EventHubConsumer(
            self,
            source_url,
            event_position=event_position,
            owner_level=owner_level,
            on_event_received=on_event_received,
            prefetch=prefetch,
            track_last_enqueued_event_properties=track_last_enqueued_event_properties)
        return handler

    @classmethod
    def from_connection_string(cls, conn_str, consumer_group, **kwargs):
        # type: (str, str, Any) -> EventHubConsumerClient
        """Create an EventHubConsumerClient from a connection string.

        :param str conn_str: The connection string of an eventhub.
        :param str consumer_group: Receive events from the event hub for this consumer group.
        :keyword str eventhub_name: The path of the specific Event Hub to connect the client to.
        :keyword bool network_tracing: Whether to output network trace logs to the logger. Default is `False`.
        :keyword dict[str,Any] http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys - 'proxy_hostname' (str value) and 'proxy_port' (int value).
         Additionally the following keys may also be present - 'username', 'password'.
        :keyword float auth_timeout: The time in seconds to wait for a token to be authorized by the service.
         The default value is 60 seconds. If set to 0, no timeout will be enforced from the client.
        :keyword str user_agent: The user agent that needs to be appended to the built in user agent string.
        :keyword int retry_total: The total number of attempts to redo the failed operation when an error happened.
         Default value is 3.
        :keyword transport_type: The type of transport protocol that will be used for communicating with
         the Event Hubs service. Default is `TransportType.Amqp`.
        :paramtype transport_type: ~azure.eventhub.TransportType
        :keyword partition_manager:
         stores the load balancing data and checkpoint data when receiving events
         if partition_manager is specified. If it's None, this EventHubConsumerClient instance will receive
         events without load balancing and checkpoint.
        :paramtype partition_manager: ~azure.eventhub.PartitionManager
        :keyword float load_balancing_interval:
         When load balancing kicks in, this is the interval in seconds between two load balancing. Default is 10.
        :rtype: ~azure.eventhub.EventHubConsumerClient

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_eventhub.py
                :start-after: [START create_eventhub_consumer_client_from_conn_str_sync]
                :end-before: [END create_eventhub_consumer_client_from_conn_str_sync]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the EventHubConsumerClient from connection string.

        """
        return super(EventHubConsumerClient, cls).from_connection_string(conn_str,
                                                                         consumer_group=consumer_group,
                                                                         **kwargs)

    def receive(self, on_event, **kwargs):
        #  type: (Callable[[PartitionContext, List[EventData]], None], str, Any) -> None
        """Receive events from partition(s) optionally with load balancing and checkpointing.

        :param on_event: The callback function for handling received event. The callback takes two
         parameters: `partition_context` which contains partition context and `event` which is the received event.
         Please define the callback like `on_event(partition_context, event)`.
         For detailed partition context information, please refer to
         :class:`PartitionContext<azure.eventhub.PartitionContext>`.
        :type on_event: Callable[~azure.eventhub.PartitionContext, EventData]
        :keyword str partition_id: Receive from this partition only if it's not None.
         Receive from all partition otherwise.
        :keyword int owner_level: The priority of the exclusive consumer. An exclusive
         consumer will be created if owner_level is set. Higher owner_level has higher exclusive priority.
        :keyword int prefetch: The number of events to prefetch from the service
         for processing. Default is 300.
        :keyword bool track_last_enqueued_event_properties: Indicates whether the consumer should request information
         on the last enqueued event on its associated partition, and track that information as events are received.
         When information about the partition's last enqueued event is being tracked, each event received from the
         Event Hubs service will carry metadata about the partition. This results in a small amount of additional
         network bandwidth consumption that is generally a favorable trade-off when considered against periodically
         making requests for partition properties using the Event Hub client.
         It is set to `False` by default.
        :keyword initial_event_position: Start receiving from this initial_event_position
         if there isn't checkpoint data for a partition. Use the checkpoint data if there it's available. This can be a
         a dict with partition id as the key and position as the value for individual partitions, or a single
         EventPosition instance for all partitions.
        :paramtype initial_event_position: ~azure.eventhub.EventPosition or dict[str,~azure.eventhub.EventPosition]
        :keyword on_error: The callback function which would be called when there is an error met during the receiving
         time. The callback takes two parameters: `partition_context` which contains partition information
         and `error` being the exception. Please define the callback like `on_error(partition_context, error)`.
        :paramtype on_error: Callable[[~azure.eventhub.PartitionContext, Exception]]
        :keyword on_partition_initialize: The callback function which will be called after a consumer for certain
         partition finishes initialization. The callback takes two parameter: `partition_context` which contains
         the partition information. Please define the callback like `on_partition_initialize(partition_context)`.
        :paramtype on_partition_initialize: Callable[[~azure.eventhub.PartitionContext]]
        :keyword on_partition_close: The callback function which will be called after a consumer for certain
         partition is closed. The callback takes two parameters: `partition_context` which contains partition
         information and `reason` for the close. Please define the callback like
         `on_partition_close(partition_context, reason)`.
         Please refer to :class:`CloseReason<azure.eventhub.CloseReason>` for different closing reason.
        :paramtype on_partition_close: Callable[[~azure.eventhub.PartitionContext, CloseReason]]
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_eventhub.py
                :start-after: [START eventhub_consumer_client_receive_sync]
                :end-before: [END eventhub_consumer_client_receive_sync]
                :language: python
                :dedent: 4
                :caption: Receive events from the EventHub.
        """
        partition_id = kwargs.get("partition_id")
        with self._lock:
            error = None
            if (self._consumer_group, ALL_PARTITIONS) in self._event_processors:
                error = ("This consumer client is already receiving events "
                         "from all partitions for consumer group {}.".format(self._consumer_group))
            elif partition_id is None and any(x[0] == self._consumer_group for x in self._event_processors):
                error = ("This consumer client is already receiving events "
                         "for consumer group {}.".format(self._consumer_group))
            elif (self._consumer_group, partition_id) in self._event_processors:
                error = ("This consumer client is already receiving events "
                         "from partition {} for consumer group {}. ".format(partition_id, self._consumer_group))
            if error:
                _LOGGER.warning(error)
                raise ValueError(error)

            event_processor = EventProcessor(
                self, self._consumer_group, on_event,
                partition_manager=self._partition_manager,
                polling_interval=self._load_balancing_interval,
                **kwargs
            )
            self._event_processors[(self._consumer_group, partition_id or ALL_PARTITIONS)] = event_processor
        try:
            event_processor.start()
        finally:
            event_processor.stop()
            with self._lock:
                try:
                    del self._event_processors[(self._consumer_group, partition_id or ALL_PARTITIONS)]
                except KeyError:
                    pass

    def close(self):
        # type: () -> None
        """Stop retrieving events from event hubs and close the underlying AMQP connection and links.

        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_eventhub.py
                :start-after: [START eventhub_consumer_client_close_sync]
                :end-before: [END eventhub_consumer_client_close_sync]
                :language: python
                :dedent: 4
                :caption: Close down the client.

        """
        with self._lock:
            for processor in self._event_processors.values():
                processor.stop()
            self._event_processors = {}
        super(EventHubConsumerClient, self).close()
