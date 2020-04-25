# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import time
import logging
import functools
from typing import Any, List, TYPE_CHECKING, Optional, Union

from uamqp import ReceiveClient, Source, types
from uamqp.constants import SenderSettleMode

from ._base_handler import BaseHandler
from ._common.utils import create_authentication
from ._common.message import PeekMessage, ReceivedMessage
from ._common.constants import (
    REQUEST_RESPONSE_RECEIVE_BY_SEQUENCE_NUMBER,
    REQUEST_RESPONSE_UPDATE_DISPOSTION_OPERATION,
    REQUEST_RESPONSE_RENEWLOCK_OPERATION,
    REQUEST_RESPONSE_PEEK_OPERATION,
    ReceiveSettleMode,
    MGMT_REQUEST_DISPOSITION_STATUS,
    MGMT_REQUEST_LOCK_TOKENS,
    MGMT_REQUEST_SEQUENCE_NUMBERS,
    MGMT_REQUEST_RECEIVER_SETTLE_MODE,
    MGMT_REQUEST_FROM_SEQUENCE_NUMBER,
    MGMT_REQUEST_MESSAGE_COUNT
)

from ._common import mgmt_handlers
from ._common.receiver_mixins import ReceiverMixin

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

_LOGGER = logging.getLogger(__name__)


class ServiceBusReceiver(BaseHandler, ReceiverMixin):  # pylint: disable=too-many-instance-attributes
    """The ServiceBusReceiver class defines a high level interface for
    receiving messages from the Azure Service Bus Queue or Topic Subscription.

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
    :keyword int prefetch: The maximum number of messages to cache with each request to the service.
     The default value is 0, meaning messages will be received from the service and processed
     one at a time. Increasing this value will improve message throughput performance but increase
     the change that messages will expire while they are cached if they're not processed fast enough.
    :keyword float idle_timeout: The timeout in seconds between received messages after which the receiver will
     automatically shutdown. The default value is 0, meaning no timeout.
    :keyword mode: The mode with which messages will be retrieved from the entity. The two options
     are PeekLock and ReceiveAndDelete. Messages received with PeekLock must be settled within a given
     lock period before they will be removed from the queue. Messages received with ReceiveAndDelete
     will be immediately removed from the queue, and cannot be subsequently rejected or re-received if
     the client fails to process the message. The default mode is PeekLock.
    :paramtype mode: ~azure.servicebus.ReceiveSettleMode
    :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
    :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
     Default value is 3.
    :keyword transport_type: The type of transport protocol that will be used for communicating with
     the Service Bus service. Default is `TransportType.Amqp`.
    :paramtype transport_type: ~azure.servicebus.TransportType
    :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
     keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
     Additionally the following keys may also be present: `'username', 'password'`.

    .. admonition:: Example:

        .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
            :start-after: [START create_servicebus_receiver_sync]
            :end-before: [END create_servicebus_receiver_sync]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the ServiceBusReceiver.

    """
    def __init__(
        self,
        fully_qualified_namespace,
        credential,
        **kwargs
    ):
        # type: (str, TokenCredential, Any) -> None
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
                entity_name=entity_name,
                **kwargs
            )
        self._message_iter = None
        self._create_attribute(**kwargs)
        self._connection = kwargs.get("connection")
        self._prefetch = kwargs.get("prefetch")

    def __iter__(self):
        return self

    def __next__(self):
        self._check_session()
        while True:
            try:
                return self._do_retryable_operation(self._iter_next)
            except StopIteration:
                self.close()
                raise

    next = __next__  # for python2.7

    def _iter_next(self):
        self._open()
        uamqp_message = next(self._message_iter)
        message = self._build_message(uamqp_message)
        return message

    def _create_handler(self, auth):
        self._handler = ReceiveClient(
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
            timeout=self._config.idle_timeout * 1000 if self._config.idle_timeout else 0,
            prefetch=self._config.prefetch
        )

    def _open(self):
        if self._running:
            return
        if self._handler:
            self._handler.close()

        auth = None if self._connection else create_authentication(self)
        self._create_handler(auth)
        try:
            self._handler.open(connection=self._connection)
            self._message_iter = self._handler.receive_messages_iter()
            while not self._handler.client_ready():
                time.sleep(0.05)
            self._running = True
        except:
            self.close()
            raise

    def _receive(self, max_batch_size=None, timeout=None):
        self._open()
        max_batch_size = max_batch_size or self._handler._prefetch  # pylint: disable=protected-access

        timeout_ms = 1000 * (timeout or self._config.idle_timeout) if (timeout or self._config.idle_timeout) else 0
        batch = self._handler.receive_message_batch(
            max_batch_size=max_batch_size,
            timeout=timeout_ms
        )

        return [self._build_message(message) for message in batch]

    def _settle_message(self, settlement, lock_tokens, dead_letter_details=None):
        message = {
            MGMT_REQUEST_DISPOSITION_STATUS: settlement,
            MGMT_REQUEST_LOCK_TOKENS: types.AMQPArray(lock_tokens)
        }

        self._populate_message_properties(message)
        if dead_letter_details:
            message.update(dead_letter_details)

        return self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_UPDATE_DISPOSTION_OPERATION,
            message,
            mgmt_handlers.default
        )

    def _renew_locks(self, *lock_tokens):
        message = {MGMT_REQUEST_LOCK_TOKENS: types.AMQPArray(lock_tokens)}
        return self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_RENEWLOCK_OPERATION,
            message,
            mgmt_handlers.lock_renew_op
        )

    @classmethod
    def from_connection_string(
        cls,
        conn_str,
        **kwargs
    ):
        # type: (str, Any) -> ServiceBusReceiver
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
         will be immediately removed from the queue, and cannot be subsequently rejected or re-received if
         the client fails to process the message. The default mode is PeekLock.
        :paramtype mode: ~azure.servicebus.ReceiveSettleMode
        :keyword int prefetch: The maximum number of messages to cache with each request to the service.
         The default value is 0, meaning messages will be received from the service and processed
         one at a time. Increasing this value will improve message throughput performance but increase
         the change that messages will expire while they are cached if they're not processed fast enough.
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
        :rtype: ~azure.servicebus.ServiceBusReceiverClient

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START create_servicebus_receiver_from_conn_str_sync]
                :end-before: [END create_servicebus_receiver_from_conn_str_sync]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the ServiceBusReceiver from connection string.

        """
        constructor_args = cls._from_connection_string(
            conn_str,
            **kwargs
        )
        if kwargs.get("queue_name") and kwargs.get("subscription_name"):
            raise ValueError("Queue entity does not have subscription.")

        if kwargs.get("topic_name") and not kwargs.get("subscription_name"):
            raise ValueError("Subscription name is missing for the topic. Please specify subscription_name.")
        return cls(**constructor_args)

    def receive(self, max_batch_size=None, max_wait_time=None):
        # type: (int, float) -> List[ReceivedMessage]
        """Receive a batch of messages at once.

        This approach it optimal if you wish to process multiple messages simultaneously. Note that the
        number of messages retrieved in a single batch will be dependent on
        whether `prefetch` was set for the receiver. This call will prioritize returning
        quickly over meeting a specified batch size, and so will return as soon as at least
        one message is received and there is a gap in incoming messages regardless
        of the specified batch size.

        :param int max_batch_size: Maximum number of messages in the batch. Actual number
         returned will depend on prefetch size and incoming stream rate.
        :param float max_wait_time: Maximum time to wait in seconds for the first message to arrive.
         If no messages arrive, and no timeout is specified, this call will not return
         until the connection is closed. If specified, an no messages arrive within the
         timeout period, an empty list will be returned.
        :rtype: list[~azure.servicebus.Message]

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START receive_sync]
                :end-before: [END receive_sync]
                :language: python
                :dedent: 4
                :caption: Receive messages from ServiceBus.

        """
        if max_batch_size and self._config.prefetch < max_batch_size:
            raise ValueError("max_batch_size should be <= prefetch of ServiceBusClient.")
        self._check_session()
        return self._do_retryable_operation(
            self._receive,
            max_batch_size=max_batch_size,
            timeout=max_wait_time,
            require_timeout=True
        )

    def receive_deferred_messages(self, sequence_numbers):
        # type: (List[int]) -> List[ReceivedMessage]
        """Receive messages that have previously been deferred.

        When receiving deferred messages from a partitioned entity, all of the supplied
        sequence numbers must be messages from the same partition.

        :param list[int] sequence_numbers: A list of the sequence numbers of messages that have been
         deferred.
        :rtype: list[~azure.servicebus.ReceivedMessage]

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START receive_defer_sync]
                :end-before: [END receive_defer_sync]
                :language: python
                :dedent: 4
                :caption: Receive deferred messages from ServiceBus.

        """
        self._check_session()
        if not sequence_numbers:
            raise ValueError("At least one sequence number must be specified.")
        self._open()
        try:
            receive_mode = self._mode.value.value
        except AttributeError:
            receive_mode = int(self._mode)
        message = {
            MGMT_REQUEST_SEQUENCE_NUMBERS: types.AMQPArray([types.AMQPLong(s) for s in sequence_numbers]),
            MGMT_REQUEST_RECEIVER_SETTLE_MODE: types.AMQPuInt(receive_mode)
        }

        self._populate_message_properties(message)

        handler = functools.partial(mgmt_handlers.deferred_message_op, mode=self._mode)
        messages = self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_RECEIVE_BY_SEQUENCE_NUMBER,
            message,
            handler
        )
        for m in messages:
            m._receiver = self  # pylint: disable=protected-access
        return messages

    def peek(self, message_count=1, sequence_number=None):
        # type: (int, Optional[int]) -> List[PeekMessage]
        """Browse messages currently pending in the queue.

        Peeked messages are not removed from queue, nor are they locked. They cannot be completed,
        deferred or dead-lettered.

        :param int message_count: The maximum number of messages to try and peek. The default
         value is 1.
        :param int sequence_number: A message sequence number from which to start browsing messages.
        :rtype: list[~azure.servicebus.PeekMessage]

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START peek_messages_sync]
                :end-before: [END peek_messages_sync]
                :language: python
                :dedent: 4
                :caption: Look at pending messages in the queue.

        """
        self._check_session()
        if not sequence_number:
            sequence_number = self._last_received_sequenced_number or 1
        if int(message_count) < 1:
            raise ValueError("count must be 1 or greater.")
        if int(sequence_number) < 1:
            raise ValueError("start_from must be 1 or greater.")

        self._open()
        message = {
            MGMT_REQUEST_FROM_SEQUENCE_NUMBER: types.AMQPLong(sequence_number),
            MGMT_REQUEST_MESSAGE_COUNT: message_count
        }

        self._populate_message_properties(message)

        return self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_PEEK_OPERATION,
            message,
            mgmt_handlers.peek_op
        )
