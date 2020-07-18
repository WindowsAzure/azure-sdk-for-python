# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import asyncio
import collections
import functools
import logging
from typing import Any, TYPE_CHECKING, List, Optional

from uamqp import ReceiveClientAsync, types, Message
from uamqp.constants import SenderSettleMode

from ._base_handler_async import BaseHandler, ServiceBusSharedKeyCredential
from ._async_message import ReceivedMessage
from .._base_handler import _convert_connection_string_to_kwargs
from .._common.receiver_mixins import ReceiverMixin
from .._common.constants import (
    REQUEST_RESPONSE_UPDATE_DISPOSTION_OPERATION,
    REQUEST_RESPONSE_PEEK_OPERATION,
    REQUEST_RESPONSE_RECEIVE_BY_SEQUENCE_NUMBER,
    REQUEST_RESPONSE_RENEWLOCK_OPERATION,
    ReceiveSettleMode,
    MGMT_REQUEST_DISPOSITION_STATUS,
    MGMT_REQUEST_LOCK_TOKENS,
    MGMT_REQUEST_SEQUENCE_NUMBERS,
    MGMT_REQUEST_RECEIVER_SETTLE_MODE,
    MGMT_REQUEST_FROM_SEQUENCE_NUMBER,
    MGMT_REQUEST_MESSAGE_COUNT
)
from .._common import mgmt_handlers
from ._async_utils import create_authentication

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

_LOGGER = logging.getLogger(__name__)


class ServiceBusReceiver(collections.abc.AsyncIterator, BaseHandler, ReceiverMixin):
    """The ServiceBusReceiver class defines a high level interface for
    receiving messages from the Azure Service Bus Queue or Topic Subscription.

    The two primary channels for message receipt are `receive()` to make a single request for messages,
    and `async for message in receiver:` to continuously receive incoming messages in an ongoing fashion.

    :ivar fully_qualified_namespace: The fully qualified host name for the Service Bus namespace.
     The namespace format is: `<yournamespace>.servicebus.windows.net`.
    :vartype fully_qualified_namespace: str
    :ivar entity_path: The path of the entity that the client connects to.
    :vartype entity_path: str

    :param str fully_qualified_namespace: The fully qualified host name for the Service Bus namespace.
     The namespace format is: `<yournamespace>.servicebus.windows.net`.
    :param ~azure.core.credentials.TokenCredential credential: The credential object used for authentication which
     implements a particular interface for getting tokens. It accepts
     :class:`ServiceBusSharedKeyCredential<azure.servicebus.ServiceBusSharedKeyCredential>`, or credential objects
     generated by the azure-identity library and objects that implement the `get_token(self, *scopes)` method.
    :keyword str queue_name: The path of specific Service Bus Queue the client connects to.
    :keyword str topic_name: The path of specific Service Bus Topic which contains the Subscription
     the client connects to.
    :keyword str subscription_name: The path of specific Service Bus Subscription under the
     specified Topic the client connects to.
    :keyword mode: The mode with which messages will be retrieved from the entity. The two options
     are PeekLock and ReceiveAndDelete. Messages received with PeekLock must be settled within a given
     lock period before they will be removed from the queue. Messages received with ReceiveAndDelete
     will be immediately removed from the queue, and cannot be subsequently abandoned or re-received
     if the client fails to process the message.
     The default mode is PeekLock.
    :paramtype mode: ~azure.servicebus.ReceiveSettleMode
    :keyword float idle_timeout: The timeout in seconds between received messages after which the receiver will
     automatically shutdown. The default value is 0, meaning no timeout.
    :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
    :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
     Default value is 3.
    :keyword transport_type: The type of transport protocol that will be used for communicating with
     the Service Bus service. Default is `TransportType.Amqp`.
    :paramtype transport_type: ~azure.servicebus.TransportType
    :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
     keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
     Additionally the following keys may also be present: `'username', 'password'`.
    :keyword str user_agent: If specified, this will be added in front of the built-in user agent string.
    :keyword int prefetch: The maximum number of messages to cache with each request to the service.
     This setting is only for advanced performance tuning. Increasing this value will improve message throughput
     performance but increase the chance that messages will expire while they are cached if they're not
     processed fast enough.
     The default value is 0, meaning messages will be received from the service and processed one at a time.
     In the case of prefetch being 0, `ServiceBusReceiver.receive` would try to cache `max_batch_size` (if provided)
     within its request to the service.

    .. admonition:: Example:

        .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
            :start-after: [START create_servicebus_receiver_async]
            :end-before: [END create_servicebus_receiver_async]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the ServiceBusReceiver.

    """
    def __init__(
        self,
        fully_qualified_namespace: str,
        credential: "TokenCredential",
        **kwargs: Any
    ):
        if kwargs.get("entity_name"):
            super(ServiceBusReceiver, self).__init__(
                fully_qualified_namespace=fully_qualified_namespace,
                credential=credential,
                **kwargs
            )
        else:
            queue_name = kwargs.get("queue_name")
            topic_name = kwargs.get("topic_name")
            subscription_name = kwargs.get("subscription_name")
            if queue_name and topic_name:
                raise ValueError("Queue/Topic name can not be specified simultaneously.")
            if not (queue_name or topic_name):
                raise ValueError("Queue/Topic name is missing. Please specify queue_name/topic_name.")
            if topic_name and not subscription_name:
                raise ValueError("Subscription name is missing for the topic. Please specify subscription_name.")

            entity_name = queue_name or topic_name

            super(ServiceBusReceiver, self).__init__(
                fully_qualified_namespace=fully_qualified_namespace,
                credential=credential,
                entity_name=str(entity_name),
                **kwargs
            )

        self._populate_attributes(**kwargs)

    async def __anext__(self):
        self._check_live()
        while True:
            try:
                return await self._do_retryable_operation(self._iter_next)
            except StopAsyncIteration:
                await self.close()
                raise

    async def _iter_next(self):
        await self._open()
        uamqp_message = await self._message_iter.__anext__()
        message = self._build_message(uamqp_message, ReceivedMessage)
        return message

    def _create_handler(self, auth):
        self._handler = ReceiveClientAsync(
            self._get_source(),
            auth=auth,
            debug=self._config.logging_enable,
            properties=self._properties,
            error_policy=self._error_policy,
            client_name=self._name,
            on_attach=self._on_attach,
            auto_complete=False,
            encoding=self._config.encoding,
            receive_settle_mode=self._mode.value,
            send_settle_mode=SenderSettleMode.Settled if self._mode == ReceiveSettleMode.ReceiveAndDelete else None,
            timeout=self._idle_timeout * 1000 if self._idle_timeout else 0,
            prefetch=self._prefetch
        )

    async def _open(self):
        if self._running:
            return
        if self._handler:
            await self._handler.close_async()
        auth = None if self._connection else (await create_authentication(self))
        self._create_handler(auth)
        try:
            await self._handler.open_async(connection=self._connection)
            self._message_iter = self._handler.receive_messages_iter_async()  # pylint: disable=attribute-defined-outside-init
            while not await self._handler.client_ready_async():
                await asyncio.sleep(0.05)
            self._running = True
        except:
            await self.close()
            raise

    async def _receive(self, max_batch_size=None, timeout=None):
        # type: (Optional[int], Optional[float]) -> List[ReceivedMessage]
        # pylint: disable=protected-access
        await self._open()

        amqp_receive_client = self._handler
        received_messages_queue = amqp_receive_client._received_messages
        max_batch_size = max_batch_size or self._prefetch
        timeout_ms = 1000 * (timeout or self._idle_timeout) if (timeout or self._idle_timeout) else 0
        abs_timeout_ms = amqp_receive_client._counter.get_current_ms() + timeout_ms if timeout_ms else 0

        batch = []  # type: List[Message]
        while not received_messages_queue.empty() and len(batch) < max_batch_size:
            batch.append(received_messages_queue.get())
            received_messages_queue.task_done()
        if len(batch) >= max_batch_size:
            return [self._build_message(message) for message in batch]

        # Dynamically issue link credit if max_batch_size > 1 when the prefetch is the default value 1
        if max_batch_size and self._prefetch == 1 and max_batch_size > 1:
            link_credit_needed = max_batch_size - len(batch)
            await amqp_receive_client.message_handler.reset_link_credit_async(link_credit_needed)

        first_message_received = expired = False
        receiving = True
        while receiving and not expired and len(batch) < max_batch_size:
            while receiving and received_messages_queue.qsize() < max_batch_size:
                if abs_timeout_ms and amqp_receive_client._counter.get_current_ms() > abs_timeout_ms:
                    expired = True
                    break
                before = received_messages_queue.qsize()
                receiving = await amqp_receive_client.do_work_async()
                received = received_messages_queue.qsize() - before
                if not first_message_received and received_messages_queue.qsize() > 0 and received > 0:
                    # first message(s) received, continue receiving for some time
                    first_message_received = True
                    abs_timeout_ms = amqp_receive_client._counter.get_current_ms() + \
                                     self._further_pull_receive_timeout_ms
            while not received_messages_queue.empty() and len(batch) < max_batch_size:
                batch.append(received_messages_queue.get())
                received_messages_queue.task_done()

        return [self._build_message(message, ReceivedMessage) for message in batch]

    async def _settle_message(self, settlement, lock_tokens, dead_letter_details=None):
        message = {
            MGMT_REQUEST_DISPOSITION_STATUS: settlement,
            MGMT_REQUEST_LOCK_TOKENS: types.AMQPArray(lock_tokens)}

        self._populate_message_properties(message)
        if dead_letter_details:
            message.update(dead_letter_details)

        return await self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_UPDATE_DISPOSTION_OPERATION,
            message,
            mgmt_handlers.default
        )

    async def _renew_locks(self, *lock_tokens):
        message = {MGMT_REQUEST_LOCK_TOKENS: types.AMQPArray(lock_tokens)}
        return await self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_RENEWLOCK_OPERATION,
            message,
            mgmt_handlers.lock_renew_op
        )

    @classmethod
    def from_connection_string(
        cls,
        conn_str: str,
        **kwargs: Any
    ) -> "ServiceBusReceiver":
        """Create a ServiceBusReceiver from a connection string.

        :param conn_str: The connection string of a Service Bus.
        :keyword str queue_name: The path of specific Service Bus Queue the client connects to.
        :keyword str topic_name: The path of specific Service Bus Topic which contains the Subscription
         the client connects to.
        :keyword str subscription_name: The path of specific Service Bus Subscription under the
         specified Topic the client connects to.
        :keyword mode: The mode with which messages will be retrieved from the entity. The two options
         are PeekLock and ReceiveAndDelete. Messages received with PeekLock must be settled within a given
         lock period before they will be removed from the queue. Messages received with ReceiveAndDelete
         will be immediately removed from the queue, and cannot be subsequently abandoned or re-received
         if the client fails to process the message.
         The default mode is PeekLock.
        :paramtype mode: ~azure.servicebus.ReceiveSettleMode
        :keyword float idle_timeout: The timeout in seconds between received messages after which the receiver will
         automatically shutdown. The default value is 0, meaning no timeout.
        :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
        :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
         Default value is 3.
        :keyword transport_type: The type of transport protocol that will be used for communicating with
         the Service Bus service. Default is `TransportType.Amqp`.
        :paramtype transport_type: ~azure.servicebus.TransportType
        :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
         Additionally the following keys may also be present: `'username', 'password'`.
        :keyword str user_agent: If specified, this will be added in front of the built-in user agent string.
        :keyword int prefetch: The maximum number of messages to cache with each request to the service.
         This setting is only for advanced performance tuning. Increasing this value will improve message throughput
         performance but increase the chance that messages will expire while they are cached if they're not
         processed fast enough.
         The default value is 0, meaning messages will be received from the service and processed one at a time.
         In the case of prefetch being 0, `ServiceBusReceiver.receive` would try to cache `max_batch_size` (if provided)
         within its request to the service.
        :rtype: ~azure.servicebus.aio.ServiceBusReceiver

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START create_servicebus_receiver_from_conn_str_async]
                :end-before: [END create_servicebus_receiver_from_conn_str_async]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the ServiceBusReceiver from connection string.

        """
        constructor_args = _convert_connection_string_to_kwargs(
            conn_str,
            ServiceBusSharedKeyCredential,
            **kwargs
        )
        if kwargs.get("queue_name") and kwargs.get("subscription_name"):
            raise ValueError("Queue entity does not have subscription.")

        if kwargs.get("topic_name") and not kwargs.get("subscription_name"):
            raise ValueError("Subscription name is missing for the topic. Please specify subscription_name.")
        return cls(**constructor_args)

    async def receive_messages(self, max_batch_size=None, max_wait_time=None):
        # type: (int, float) -> List[ReceivedMessage]
        """Receive a batch of messages at once.

        This approach is optimal if you wish to process multiple messages simultaneously, or
        perform an ad-hoc receive as a single call.

        Note that the number of messages retrieved in a single batch will be dependent on
        whether `prefetch` was set for the receiver. If `prefetch` is not set for the receiver, the receiver would
        try to cache max_batch_size (if provided) messages within the request to the service.

        This call will prioritize returning quickly over meeting a specified batch size, and so will
        return as soon as at least one message is received and there is a gap in incoming messages regardless
        of the specified batch size.

        :param int max_batch_size: Maximum number of messages in the batch. Actual number
         returned will depend on prefetch size and incoming stream rate.
        :param float max_wait_time: Maximum time to wait in seconds for the first message to arrive.
         If no messages arrive, and no timeout is specified, this call will not return
         until the connection is closed. If specified, an no messages arrive within the
         timeout period, an empty list will be returned.
        :rtype: list[~azure.servicebus.aio.ReceivedMessage]

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START receive_async]
                :end-before: [END receive_async]
                :language: python
                :dedent: 4
                :caption: Receive messages from ServiceBus.

        """
        self._check_live()
        return await self._do_retryable_operation(
            self._receive,
            max_batch_size=max_batch_size,
            timeout=max_wait_time,
            require_timeout=True
        )

    async def receive_deferred_messages(self, sequence_numbers):
        # type: (List[int]) -> List[ReceivedMessage]
        """Receive messages that have previously been deferred.

        When receiving deferred messages from a partitioned entity, all of the supplied
        sequence numbers must be messages from the same partition.

        :param list[int] sequence_numbers: A list of the sequence numbers of messages that have been
         deferred.
        :rtype: list[~azure.servicebus.aio.ReceivedMessage]

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START receive_defer_async]
                :end-before: [END receive_defer_async]
                :language: python
                :dedent: 4
                :caption: Receive deferred messages from ServiceBus.

        """
        self._check_live()
        if not sequence_numbers:
            raise ValueError("At least one sequence number must be specified.")
        await self._open()
        try:
            receive_mode = self._mode.value.value
        except AttributeError:
            receive_mode = int(self._mode)
        message = {
            MGMT_REQUEST_SEQUENCE_NUMBERS: types.AMQPArray([types.AMQPLong(s) for s in sequence_numbers]),
            MGMT_REQUEST_RECEIVER_SETTLE_MODE: types.AMQPuInt(receive_mode)
        }

        self._populate_message_properties(message)

        handler = functools.partial(mgmt_handlers.deferred_message_op, mode=self._mode, message_type=ReceivedMessage)
        messages = await self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_RECEIVE_BY_SEQUENCE_NUMBER,
            message,
            handler
        )
        for m in messages:
            m._receiver = self  # pylint: disable=protected-access
        return messages

    async def peek_messages(self, message_count=1, sequence_number=0):
        """Browse messages currently pending in the queue.

        Peeked messages are not removed from queue, nor are they locked. They cannot be completed,
        deferred or dead-lettered.

        :param int message_count: The maximum number of messages to try and peek. The default
         value is 1.
        :param int sequence_number: A message sequence number from which to start browsing messages.
        :rtype: list[~azure.servicebus.PeekMessage]

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START peek_messages_async]
                :end-before: [END peek_messages_async]
                :language: python
                :dedent: 4
                :caption: Peek messages in the queue.
        """
        self._check_live()
        if not sequence_number:
            sequence_number = self._last_received_sequenced_number or 1
        if int(message_count) < 1:
            raise ValueError("count must be 1 or greater.")
        if int(sequence_number) < 1:
            raise ValueError("start_from must be 1 or greater.")

        await self._open()

        message = {
            MGMT_REQUEST_FROM_SEQUENCE_NUMBER: types.AMQPLong(sequence_number),
            MGMT_REQUEST_MESSAGE_COUNT: message_count
        }

        self._populate_message_properties(message)

        return await self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_PEEK_OPERATION,
            message,
            mgmt_handlers.peek_op
        )
