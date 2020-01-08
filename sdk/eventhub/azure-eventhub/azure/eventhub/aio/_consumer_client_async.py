# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import asyncio
import logging
import datetime
from typing import (
    Any,
    Union,
    TYPE_CHECKING,
    Dict,
    Tuple,
    Callable,
    Optional,
    List,
    Awaitable,
)

from ._eventprocessor.event_processor import EventProcessor
from ._consumer_async import EventHubConsumer
from ._client_base_async import ClientBaseAsync
from .._constants import ALL_PARTITIONS


if TYPE_CHECKING:
    from uamqp.constants import TransportType
    from azure.core.credentials import TokenCredential
    from ._eventprocessor.partition_context import PartitionContext
    from ._eventprocessor.checkpoint_store import CheckpointStore
    from .._common import EventData
    from .._eventprocessor.common import CloseReason

_LOGGER = logging.getLogger(__name__)


class EventHubConsumerClient(ClientBaseAsync):
    """The EventHubConsumerClient class defines a high level interface for
    receiving events from the Azure Event Hubs service.

    The main goal of `EventHubConsumerClient` is to receive events from all partitions of an EventHub with
    load-balancing and checkpointing.

    When multiple `EventHubConsumerClient` operate within one or more processes or machines targeting the same
    checkpointing location, they will balance automatically.
    To enable the load-balancing, checkpoint_store must be set when creating the `EventHubConsumerClient`.

    An `EventHubConsumerClient` can also receive from a specific partition when you call its method `receive()`
    and specify the partition_id. Load-balancing won't work in single-partition receiving mode.

    :param str fully_qualified_namespace: The fully qualified host name for the Event Hubs namespace.
     The format is like `<yournamespace>.servicebus.windows.net`.
    :param str eventhub_name: The path of the specific Event Hub to connect the client to.
    :param str consumer_group: Receive events from the event hub for this consumer group.
    :param ~azure.core.credentials.TokenCredential credential: The credential object used for authentication which
     implements a particular interface for getting tokens. It accepts
     :class:`EventHubSharedKeyCredential<azure.eventhub.aio.EventHubSharedKeyCredential>`, or credential objects
     generated by the azure-identity library and objects that implement the `get_token(self, *scopes)` method.
    :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
    :keyword float auth_timeout: The time in seconds to wait for a token to be authorized by the service.
     The default value is 60 seconds. If set to 0, no timeout will be enforced from the client.
    :keyword str user_agent: The user agent that should be appended to the built-in user agent string.
    :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
     Default value is 3. The context of `retry_total` in receiving is special: The `receive` method is implemented
     by a while-loop calling internal receive method in each iteration. In the `receive` case,
     `retry_total` specifies the numbers of retry after error raised by internal receive method in the while-loop.
     If retry attempts are exhausted, the `on_error` callback will be called (if provided) with the error information.
     The failed internal partition consumer will be closed (`on_partition_close` will be called if provided) and
     new internal partition consumer will be created (`on_partition_initialize` will be called if provided) to resume
     receiving.
    :keyword float idle_timeout: Timeout in seconds after which the underlying connection will close
     if there is no further activity. By default the value is None, meaning that the service determines when to
     close an idle connection.
    :keyword transport_type: The type of transport protocol that will be used for communicating with
     the Event Hubs service. Default is `TransportType.Amqp`.
    :paramtype transport_type: ~azure.eventhub.TransportType
    :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
     keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
     Additionally the following keys may also be present: `'username', 'password'`.
    :keyword checkpoint_store: A manager that stores the partition load-balancing and checkpoint data
     when receiving events. The checkpoint store will be used in both cases of receiving from all partitions
     or a single partition. In the latter case load-balancing does not apply.
     If a checkpoint store is not provided, the checkpoint will be maintained internally
     in memory, and the `EventHubConsumerClient` instance will receive events without load-balancing.
    :paramtype checkpoint_store: ~azure.eventhub.aio.CheckpointStore
    :keyword float load_balancing_interval: When load-balancing kicks in. This is the interval, in seconds,
     between two load-balancing evaluations. Default is 10 seconds.

    .. admonition:: Example:

        .. literalinclude:: ../samples/async_samples/sample_code_eventhub_async.py
            :start-after: [START create_eventhub_consumer_client_async]
            :end-before: [END create_eventhub_consumer_client_async]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the EventHubConsumerClient.
    """

    def __init__(
        self,
        fully_qualified_namespace: str,
        eventhub_name: str,
        consumer_group: str,
        credential: "TokenCredential",
        **kwargs
    ) -> None:
        self._checkpoint_store = kwargs.pop("checkpoint_store", None)
        self._load_balancing_interval = kwargs.pop("load_balancing_interval", 10)
        self._consumer_group = consumer_group
        network_tracing = kwargs.pop("logging_enable", False)
        super(EventHubConsumerClient, self).__init__(
            fully_qualified_namespace=fully_qualified_namespace,
            eventhub_name=eventhub_name,
            credential=credential,
            network_tracing=network_tracing,
            **kwargs
        )
        self._lock = asyncio.Lock(loop=self._loop)
        self._event_processors = dict()  # type: Dict[Tuple[str, str], EventProcessor]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def _create_consumer(
        self,
        consumer_group: str,
        partition_id: str,
        event_position: Union[str, int, datetime.datetime],
        on_event_received: Callable[["PartitionContext", "EventData"], Awaitable[None]],
        **kwargs
    ) -> EventHubConsumer:
        owner_level = kwargs.get("owner_level")
        prefetch = kwargs.get("prefetch") or self._config.prefetch
        track_last_enqueued_event_properties = kwargs.get(
            "track_last_enqueued_event_properties", False
        )
        event_position_inclusive = kwargs.get("event_position_inclusive", False)

        source_url = "amqps://{}{}/ConsumerGroups/{}/Partitions/{}".format(
            self._address.hostname, self._address.path, consumer_group, partition_id
        )
        handler = EventHubConsumer(
            self,
            source_url,
            on_event_received=on_event_received,
            event_position=event_position,
            event_position_inclusive=event_position_inclusive,
            owner_level=owner_level,
            prefetch=prefetch,
            idle_timeout=self._idle_timeout,
            track_last_enqueued_event_properties=track_last_enqueued_event_properties,
            loop=self._loop,
        )
        return handler

    @classmethod
    def from_connection_string(
        cls,
        conn_str: str,
        consumer_group: str,
        *,
        eventhub_name: Optional[str] = None,
        logging_enable: bool = False,
        http_proxy: Optional[Dict[str, Union[str, int]]] = None,
        auth_timeout: float = 60,
        user_agent: Optional[str] = None,
        retry_total: int = 3,
        transport_type: Optional["TransportType"] = None,
        checkpoint_store: Optional["CheckpointStore"] = None,
        load_balancing_interval: float = 10,
        **kwargs: Any
    ) -> "EventHubConsumerClient":
        """Create an EventHubConsumerClient from a connection string.

        :param str conn_str: The connection string of an Event Hub.
        :param str consumer_group: Receive events from the Event Hub for this consumer group.
        :keyword str eventhub_name: The path of the specific Event Hub to connect the client to.
        :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
        :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
         Additionally the following keys may also be present: `'username', 'password'`.
        :keyword float auth_timeout: The time in seconds to wait for a token to be authorized by the service.
         The default value is 60 seconds. If set to 0, no timeout will be enforced from the client.
        :keyword str user_agent: The user agent that should be appended to the built-in user agent string.
        :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
         Default value is 3. The context of `retry_total` in receiving is special: The `receive` method is implemented
         by a while-loop calling internal receive method in each iteration. In the `receive` case,
         `retry_total` specifies the numbers of retry after error raised by internal receive method in the while-loop.
         If retry attempts are exhausted, the `on_error` callback will be called (if provided) with the error
         information. The failed internal partition consumer will be closed (`on_partition_close` will be called
         if provided) and new internal partition consumer will be created (`on_partition_initialize` will be called if
         provided) to resume receiving.
        :keyword float idle_timeout: Timeout in seconds after which the underlying connection will close
         if there is no further activity. By default the value is None, meaning that the service determines when to
         close an idle connection.
        :keyword transport_type: The type of transport protocol that will be used for communicating with
         the Event Hubs service. Default is `TransportType.Amqp`.
        :paramtype transport_type: ~azure.eventhub.TransportType
        :keyword checkpoint_store: A manager that stores the partition load-balancing and checkpoint data
         when receiving events. The checkpoint store will be used in both cases of receiving from all partitions
         or a single partition. In the latter case load-balancing does not apply.
         If a checkpoint store is not provided, the checkpoint will be maintained internally
         in memory, and the `EventHubConsumerClient` instance will receive events without load-balancing.
        :paramtype checkpoint_store: ~azure.eventhub.aio.CheckpointStore
        :keyword float load_balancing_interval: When load-balancing kicks in. This is the interval, in seconds,
         between two load-balancing evaluations. Default is 10 seconds.
        :rtype: ~azure.eventhub.aio.EventHubConsumerClient

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_eventhub_async.py
                :start-after: [START create_eventhub_consumer_client_from_conn_str_async]
                :end-before: [END create_eventhub_consumer_client_from_conn_str_async]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the EventHubConsumerClient from connection string.

        """
        constructor_args = cls._from_connection_string(
            conn_str,
            consumer_group=consumer_group,
            eventhub_name=eventhub_name,
            logging_enable=logging_enable,
            http_proxy=http_proxy,
            auth_timeout=auth_timeout,
            user_agent=user_agent,
            retry_total=retry_total,
            transport_type=transport_type,
            checkpoint_store=checkpoint_store,
            load_balancing_interval=load_balancing_interval,
            **kwargs
        )
        return cls(**constructor_args)

    async def receive(
        self,
        on_event: Callable[["PartitionContext", "EventData"], Awaitable[None]],
        *,
        partition_id: Optional[str] = None,
        owner_level: Optional[int] = None,
        prefetch: int = 300,
        track_last_enqueued_event_properties: bool = False,
        starting_position: Optional[
            Union[str, int, datetime.datetime, Dict[str, Any]]
        ] = None,
        starting_position_inclusive: Union[bool, Dict[str, bool]] = False,
        on_error: Optional[
            Callable[["PartitionContext", Exception], Awaitable[None]]
        ] = None,
        on_partition_initialize: Optional[
            Callable[["PartitionContext"], Awaitable[None]]
        ] = None,
        on_partition_close: Optional[
            Callable[["PartitionContext", "CloseReason"], Awaitable[None]]
        ] = None
    ) -> None:
        """Receive events from partition(s), with optional load-balancing and checkpointing.

        :param on_event: The callback function for handling a received event. The callback takes two
         parameters: `partition_context` which contains partition context and `event` which is the received event.
         The callback function should be defined like: `on_event(partition_context, event)`.
         For detailed partition context information, please refer to
         :class:`PartitionContext<azure.eventhub.aio.PartitionContext>`.
        :type on_event: Callable[~azure.eventhub.aio.PartitionContext, ~azure.eventhub.EventData]
        :keyword str partition_id: If specified, the client will receive from this partition only.
         Otherwise the client will receive from all partitions.
        :keyword int owner_level: The priority for an exclusive consumer. An exclusive
         consumer will be created if owner_level is set. A consumer with a higher owner_level has higher exclusive
         priority. The owner level is also know as the 'epoch value' of the consumer.
        :keyword int prefetch: The number of events to prefetch from the service
         for processing. Default is 300.
        :keyword bool track_last_enqueued_event_properties: Indicates whether the consumer should request information
         on the last-enqueued event on its associated partition, and track that information as events are received.
         When information about the partitions last-enqueued event is being tracked, each event received from the
         Event Hubs service will carry metadata about the partition. This results in a small amount of additional
         network bandwidth consumption that is generally a favorable trade-off when considered against periodically
         making requests for partition properties using the Event Hub client.
         It is set to `False` by default.
        :keyword starting_position: Start receiving from this event position
         if there is no checkpoint data for a partition. Checkpoint data will be used if available. This can be a
         a dict with partition ID as the key and position as the value for individual partitions, or a single
         value for all partitions. The value type can be str, int, datetime.datetime. Also supported are the
         values "-1" for receiving from the beginning of the stream, and "@latest" for receiving only new events.
        :paramtype starting_position: str, int, datetime.datetime or dict[str,Any]
        :keyword starting_position_inclusive: Determine whether the given starting_position is inclusive(>=) or
         not (>). True for inclusive and False for exclusive. This can be a dict with partition ID as the key and
         bool as the value indicating whether the starting_position for a specific partition is inclusive or not.
         This can also be a single bool value for all starting_position. The default value is False.
        :paramtype starting_position_inclusive: bool or dict[str,bool]
        :keyword on_error: The callback function that will be called when an error is raised during receiving
         after retry attempts are exhausted, or during the process of load-balancing.
         The callback takes two parameters: `partition_context` which contains partition information
         and `error` being the exception. `partition_context` could be None if the error is raised during
         the process of load-balance. The callback should be defined like: `on_error(partition_context, error)`.
         The `on_error` callback will also be called if an unhandled exception is raised during
         the `on_event` callback.
        :paramtype on_error: Callable[[~azure.eventhub.aio.PartitionContext, Exception]]
        :keyword on_partition_initialize: The callback function that will be called after a consumer for a certain
         partition finishes initialization. It would also be called when a new internal partition consumer is created
         to take over the receiving process for a failed and closed internal partition consumer.
         The callback takes a single parameter: `partition_context`
         which contains the partition information. The callback should be defined
         like: `on_partition_initialize(partition_context)`.
        :paramtype on_partition_initialize: Callable[[~azure.eventhub.aio.PartitionContext]]
        :keyword on_partition_close: The callback function that will be called after a consumer for a certain
         partition is closed. It would be also called when error is raised during receiving after retry attempts are
         exhausted. The callback takes two parameters: `partition_context` which contains partition
         information and `reason` for the close. The callback should be defined like:
         `on_partition_close(partition_context, reason)`.
         Please refer to :class:`CloseReason<azure.eventhub.CloseReason>` for the various closing reasons.
        :paramtype on_partition_close: Callable[[~azure.eventhub.aio.PartitionContext, ~azure.eventhub.CloseReason]]
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_eventhub_async.py
                :start-after: [START eventhub_consumer_client_receive_async]
                :end-before: [END eventhub_consumer_client_receive_async]
                :language: python
                :dedent: 4
                :caption: Receive events from the EventHub.
        """
        async with self._lock:
            error = None
            if (self._consumer_group, ALL_PARTITIONS) in self._event_processors:
                error = (
                    "This consumer client is already receiving events "
                    "from all partitions for consumer group {}. ".format(
                        self._consumer_group
                    )
                )
            elif partition_id is None and any(
                x[0] == self._consumer_group for x in self._event_processors
            ):
                error = (
                    "This consumer client is already receiving events "
                    "for consumer group {}. ".format(self._consumer_group)
                )
            elif (self._consumer_group, partition_id) in self._event_processors:
                error = (
                    "This consumer client is already receiving events "
                    "from partition {} for consumer group {}. ".format(
                        partition_id, self._consumer_group
                    )
                )
            if error:
                _LOGGER.warning(error)
                raise ValueError(error)

            event_processor = EventProcessor(
                self,
                self._consumer_group,
                on_event,
                partition_id=partition_id,
                checkpoint_store=self._checkpoint_store,
                error_handler=on_error,
                partition_initialize_handler=on_partition_initialize,
                partition_close_handler=on_partition_close,
                load_balancing_interval=self._load_balancing_interval,
                initial_event_position=starting_position if starting_position is not None else "@latest",
                initial_event_position_inclusive=starting_position_inclusive or False,
                owner_level=owner_level,
                prefetch=prefetch,
                track_last_enqueued_event_properties=track_last_enqueued_event_properties,
                loop=self._loop,
            )
            self._event_processors[
                (self._consumer_group, partition_id or ALL_PARTITIONS)
            ] = event_processor
        try:
            await event_processor.start()
        finally:
            await event_processor.stop()
            async with self._lock:
                try:
                    del self._event_processors[
                        (self._consumer_group, partition_id or ALL_PARTITIONS)
                    ]
                except KeyError:
                    pass

    async def get_eventhub_properties(self) -> Dict[str, Any]:
        """Get properties of the Event Hub.

        Keys in the returned dictionary include:

            - `eventhub_name` (str)
            - `created_at` (UTC datetime.datetime)
            - `partition_ids` (list[str])

        :rtype: dict
        :raises: :class:`EventHubError<azure.eventhub.exceptions.EventHubError>`
        """
        return await super(
            EventHubConsumerClient, self
        )._get_eventhub_properties_async()

    async def get_partition_ids(self) -> List[str]:
        """Get partition IDs of the Event Hub.

        :rtype: list[str]
        :raises: :class:`EventHubError<azure.eventhub.exceptions.EventHubError>`
        """
        return await super(EventHubConsumerClient, self)._get_partition_ids_async()

    async def get_partition_properties(self, partition_id: str) -> Dict[str, Any]:
        """Get properties of the specified partition.

        Keys in the properties dictionary include:

            - `eventhub_name` (str)
            - `id` (str)
            - `beginning_sequence_number` (int)
            - `last_enqueued_sequence_number` (int)
            - `last_enqueued_offset` (str)
            - `last_enqueued_time_utc` (UTC datetime.datetime)
            - `is_empty` (bool)

        :param partition_id: The target partition ID.
        :type partition_id: str
        :rtype: dict
        :raises: :class:`EventHubError<azure.eventhub.exceptions.EventHubError>`
        """
        return await super(
            EventHubConsumerClient, self
        )._get_partition_properties_async(partition_id)

    async def close(self) -> None:
        """Stop retrieving events from the Event Hub and close the underlying AMQP connection and links.

        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_eventhub_async.py
                :start-after: [START eventhub_consumer_client_close_async]
                :end-before: [END eventhub_consumer_client_close_async]
                :language: python
                :dedent: 4
                :caption: Close down the client.

        """
        async with self._lock:
            await asyncio.gather(
                *[p.stop() for p in self._event_processors.values()],
                return_exceptions=True,
                loop=self._loop
            )
            self._event_processors = {}
            await super(EventHubConsumerClient, self)._close_async()
