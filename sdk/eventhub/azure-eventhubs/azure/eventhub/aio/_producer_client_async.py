# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import asyncio
import logging

from typing import Any, Union, TYPE_CHECKING, Iterable, List
from uamqp import constants  # type: ignore
from azure.eventhub import EventData, \
    EventHubSharedKeyCredential, EventHubSASTokenCredential, EventDataBatch
from .client_async import EventHubClient
from .producer_async import EventHubProducer

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential  # type: ignore

log = logging.getLogger(__name__)


class EventHubProducerClient(EventHubClient):
    """Represents an AMQP connection to an EventHub and receives event data from it.

    Example:
        .. literalinclude:: ../samples/test_examples_eventhub_async.py
            :start-after: [START create_eventhub_producer_client_async]
            :end-before: [END create_eventhub_producer_client_async]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the EventHubProducerClient.
    """

    def __init__(self, host, event_hub_path, credential, **kwargs):
        # type:(str, str, Union[EventHubSharedKeyCredential, EventHubSASTokenCredential, TokenCredential], Any) -> None
        """
        :param host: The hostname of the Event Hub.
        :type host: str
        :param event_hub_path: The path of the specific Event Hub to connect the client to.
        :type event_hub_path: str
        :param network_tracing: Whether to output network trace logs to the logger. Default
         is `False`.
        :type network_tracing: bool
        :param credential: The credential object used for authentication which implements particular interface
         of getting tokens. It accepts ~azure.eventhub.EventHubSharedKeyCredential,
         ~azure.eventhub.EventHubSASTokenCredential, credential objects generated by the azure-identity library and
         objects that implement get_token(self, *scopes) method.
        :param http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: 'proxy_hostname' (str value) and 'proxy_port' (int value).
         Additionally the following keys may also be present: 'username', 'password'.
        :type http_proxy: dict[str, Any]
        :param auth_timeout: The time in seconds to wait for a token to be authorized by the service.
         The default value is 60 seconds. If set to 0, no timeout will be enforced from the client.
        :type auth_timeout: float
        :param user_agent: The user agent that needs to be appended to the built in user agent string.
        :type user_agent: str
        :param retry_total: The total number of attempts to redo the failed operation when an error happened. Default
         value is 3.
        :type retry_total: int
        :param transport_type: The type of transport protocol that will be used for communicating with
         the Event Hubs service. Default is ~azure.eventhub.TransportType.Amqp.
        :type transport_type: ~azure.eventhub.TransportType
        """
        super(EventHubProducerClient, self).__init__(
            host=host, event_hub_path=event_hub_path, credential=credential, **kwargs)
        self._producers = []  # type: List[EventHubProducer]
        self._client_lock = asyncio.Lock()  # sync the creation of self._producers
        self._producers_locks = []  # type: List[asyncio.Lock]
        self._max_message_size_on_link = 0

    async def _init_locks_for_producers(self):
        if not self._producers:
            async with self._client_lock:
                if not self._producers:
                    num_of_producers = len(await self.get_partition_ids()) + 1
                    self._producers = [None] * num_of_producers
                    for _ in range(num_of_producers):
                        self._producers_locks.append(asyncio.Lock())
                        # self._producers_locks = [asyncio.Lock()] * num_of_producers

    async def send(self, event_data: Union[EventData, EventDataBatch, Iterable[EventData]],
            *, partition_key: Union[str, bytes] = None, partition_id: str = None, timeout: float = None) -> None:
        """Sends an event data and blocks until acknowledgement is received or operation times out.

        :param event_data: The event(s) to be sent. It can be an EventData object, an iterable of EventData objects
            or an EventDataBatch, which contains some EventData objects. EventDataBatch is highly recommended to group
            as many EventData objects as possible in a single send call. This will maximize the send throughput.
            A send operation will send all EventData objects to one partition.
            Multiple send operations will round-robin send to partitions alternately.
            Round-robin is the recommended and the default behavior of send
            unless you set partition_id or partition_key.
        :param partition_id: event_data will be sent to this partition. This is not recommended because it may
         cause unbalanced number of event data across partitions.
        :param partition_key: With the given partition_key, event_data will land to
         a particular partition but unknown until the send completes. Two send operations with the same partition_key
         will go to the same partition even though which the partition is unknown while before send.
        :param timeout: The maximum wait time to send the event data.
         Default value is 60 seconds. If set to 0, there will be no timeout.

        :raises: ~azure.eventhub.AuthenticationError, ~azure.eventhub.ConnectError, ~azure.eventhub.ConnectionLostError,
                ~azure.eventhub.EventDataError, ~azure.eventhub.EventDataSendError, ~azure.eventhub.EventHubError
        :return: None
        :rtype: None

        Example:
            .. literalinclude:: ../samples/test_examples_eventhub_async.py
                :start-after: [START eventhub_producer_client_send_async]
                :end-before: [END eventhub_producer_client_send_async]
                :language: python
                :dedent: 4
                :caption: Asynchronously sends an event data

        """

        await self._init_locks_for_producers()

        producer_index = int(partition_id) if partition_id is not None else -1
        if self._producers[producer_index] is None or self._producers[producer_index]._closed:  # pylint:disable=protected-access
            async with self._producers_locks[producer_index]:
                if self._producers[producer_index] is None:
                    self._producers[producer_index] = self._create_producer(partition_id=partition_id)
        async with self._producers_locks[producer_index]:
            await self._producers[producer_index].send(event_data, partition_key=partition_key, timeout=timeout)

    async def create_batch(self, max_size=None):
        # type:(int) -> EventDataBatch
        """
        Create an EventDataBatch object with max size being max_size.
        The max_size should be no greater than the max allowed message size defined by the service side.

        :param max_size: The maximum size of bytes data that an EventDataBatch object can hold.
        :type max_size: int
        :return: an EventDataBatch instance
        :rtype: ~azure.eventhub.EventDataBatch

        Example:
            .. literalinclude:: ../examples/test_examples_eventhub_async.py
                :start-after: [START eventhub_producer_client_create_batch_async]
                :end-before: [END eventhub_producer_client_create_batch_async]
                :language: python
                :dedent: 4
                :caption: Create EventDataBatch object within limited size

        """
        if not self._max_message_size_on_link:
            await self._init_locks_for_producers()
            async with self._producers_locks[-1]:
                if self._producers[-1] is None:
                    self._producers[-1] = self._create_producer(partition_id=None)
                    await self._producers[-1]._open_with_retry()  # pylint: disable=protected-access
            async with self._client_lock:
                self._max_message_size_on_link = \
                    self._producers[-1]._handler.message_handler._link.peer_max_message_size or constants.MAX_MESSAGE_LENGTH_BYTES  # pylint: disable=protected-access, line-too-long

        if max_size and max_size > self._max_message_size_on_link:
            raise ValueError('Max message size: {} is too large, acceptable max batch size is: {} bytes.'
                             .format(max_size, self._max_message_size_on_link))

        return EventDataBatch(max_size=(max_size or self._max_message_size_on_link))

    async def close(self):
        # type: () -> None
        """
        Close down the handler. If the handler has already closed,
        this will be a no op.

        Example:
            .. literalinclude:: ../examples/test_examples_eventhub_async.py
                :start-after: [START eventhub_producer_client_close_async]
                :end-before: [END eventhub_producer_client_close_async]
                :language: python
                :dedent: 4
                :caption: Close down the handler.

        """
        if self._producers:
            for p in self._producers:
                if p:
                    await p.close()
        await self._conn_manager.close_connection()
