# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import logging
import asyncio
from typing import Any, TYPE_CHECKING, Union, List

import uamqp
from uamqp import SendClientAsync, types

from .._common.message import Message, BatchMessage
from .._servicebus_sender import SenderMixin
from ._base_handler_async import BaseHandlerAsync
from ..exceptions import (
    MessageError
)
from .._common.constants import (
    REQUEST_RESPONSE_SCHEDULE_MESSAGE_OPERATION,
    REQUEST_RESPONSE_CANCEL_SCHEDULED_MESSAGE_OPERATION,
    MGMT_REQUEST_SEQUENCE_NUMBERS
)
from .._common import mgmt_handlers
from ._async_utils import create_authentication

if TYPE_CHECKING:
    import datetime
    from azure.core.credentials import TokenCredential

_LOGGER = logging.getLogger(__name__)


class ServiceBusSender(BaseHandlerAsync, SenderMixin):
    """The ServiceBusSender class defines a high level interface for
    sending messages to the Azure Service Bus Queue or Topic.

    :ivar fully_qualified_namespace: The fully qualified host name for the Service Bus namespace.
     The namespace format is: `<yournamespace>.servicebus.windows.net`.
    :vartype fully_qualified_namespace: str
    :ivar entity_name: The name of the entity that the client connects to.
    :vartype entity_name: str

    :param str fully_qualified_namespace: The fully qualified host name for the Service Bus namespace.
     The namespace format is: `<yournamespace>.servicebus.windows.net`.
    :param ~azure.core.credentials.TokenCredential credential: The credential object used for authentication which
     implements a particular interface for getting tokens. It accepts
     :class:`ServiceBusSharedKeyCredential<azure.servicebus.ServiceBusSharedKeyCredential>`, or credential objects
     generated by the azure-identity library and objects that implement the `get_token(self, *scopes)` method.
    :keyword str queue_name: The path of specific Service Bus Queue the client connects to.
     Only one of queue_name or topic_name can be provided.
    :keyword str topic_name: The path of specific Service Bus Topic the client connects to.
     Only one of queue_name or topic_name can be provided.
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

        .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
            :start-after: [START create_servicebus_sender_async]
            :end-before: [END create_servicebus_sender_async]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the ServiceBusSender.

    """
    def __init__(
        self,
        fully_qualified_namespace: str,
        credential: "TokenCredential",
        **kwargs: Any
    ):
        if kwargs.get("entity_name"):
            super(ServiceBusSender, self).__init__(
                fully_qualified_namespace=fully_qualified_namespace,
                credential=credential,
                **kwargs
            )
        else:
            queue_name = kwargs.get("queue_name")
            topic_name = kwargs.get("topic_name")
            if queue_name and topic_name:
                raise ValueError("Queue/Topic name can not be specified simultaneously.")
            if not (queue_name or topic_name):
                raise ValueError("Queue/Topic name is missing. Please specify queue_name/topic_name.")
            entity_name = queue_name or topic_name
            super(ServiceBusSender, self).__init__(
                fully_qualified_namespace=fully_qualified_namespace,
                credential=credential,
                entity_name=str(entity_name),
                **kwargs
            )

        self._max_message_size_on_link = 0
        self._create_attribute()
        self._connection = kwargs.get("connection")

    def _create_handler(self, auth):
        self._handler = SendClientAsync(
            self._entity_uri,
            auth=auth,
            debug=self._config.logging_enable,
            properties=self._properties,
            error_policy=self._error_policy,
            client_name=self._name,
            encoding=self._config.encoding
        )

    async def _open(self):
        # pylint: disable=protected-access
        if self._running:
            return
        if self._handler:
            await self._handler.close_async()
        auth = None if self._connection else (await create_authentication(self))
        self._create_handler(auth)
        try:
            await self._handler.open_async(connection=self._connection)
            while not await self._handler.client_ready_async():
                await asyncio.sleep(0.05)
            self._running = True
            self._max_message_size_on_link = self._handler.message_handler._link.peer_max_message_size \
                                             or uamqp.constants.MAX_MESSAGE_LENGTH_BYTES
        except:
            self.close()
            raise

    async def _send(self, message, timeout=None, last_exception=None):
        await self._open()
        self._set_msg_timeout(timeout, last_exception)
        await self._handler.send_message_async(message.message)

    async def _schedule(self, message, schedule_time_utc):
        # type: (Union[Message, BatchMessage], datetime.datetime) -> List[int]
        """Send Message or BatchMessage to be enqueued at a specific time.
        Returns a list of the sequence numbers of the enqueued messages.
        :param message: The messages to schedule.
        :type message: ~azure.servicebus.Message or ~azure.servicebus.BatchMessage
        :param schedule_time_utc: The utc date and time to enqueue the messages.
        :type schedule_time_utc: ~datetime.datetime
        :rtype: List[int]

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START scheduling_messages_async]
                :end-before: [END scheduling_messages_async]
                :language: python
                :dedent: 4
                :caption: Schedule a message to be sent in future
        """
        # pylint: disable=protected-access
        await self._open()
        if isinstance(message, BatchMessage):
            request_body = self._build_schedule_request(schedule_time_utc, *message._messages)
        else:
            request_body = self._build_schedule_request(schedule_time_utc, message)
        return await self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_SCHEDULE_MESSAGE_OPERATION,
            request_body,
            mgmt_handlers.schedule_op
        )

    async def _cancel_scheduled_messages(self, sequence_numbers):
        # type: (Union[int, List[int]]) -> None
        """
        Cancel one or more messages that have previously been scheduled and are still pending.

        :param sequence_numbers: he sequence numbers of the scheduled messages.
        :type sequence_numbers: int or list[int]
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START cancel_scheduled_messages_async]
                :end-before: [END cancel_scheduled_messages_async]
                :language: python
                :dedent: 4
                :caption: Cancelling messages scheduled to be sent in future
        """
        await self._open()
        if isinstance(sequence_numbers, int):
            numbers = [types.AMQPLong(sequence_numbers)]
        else:
            numbers = [types.AMQPLong(s) for s in sequence_numbers]
        request_body = {MGMT_REQUEST_SEQUENCE_NUMBERS: types.AMQPArray(numbers)}
        return await self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_CANCEL_SCHEDULED_MESSAGE_OPERATION,
            request_body,
            mgmt_handlers.default
        )

    @classmethod
    def from_connection_string(
        cls,
        conn_str: str,
        **kwargs: Any
    ) -> "ServiceBusSender":
        """Create a ServiceBusSender from a connection string.

        :param conn_str: The connection string of a Service Bus.
        :keyword str queue_name: The path of specific Service Bus Queue the client connects to.
        :keyword str topic_name: The path of specific Service Bus Topic the client connects to.
        :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
        :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
         Default value is 3.
        :keyword transport_type: The type of transport protocol that will be used for communicating with
         the Service Bus service. Default is `TransportType.Amqp`.
        :paramtype transport_type: ~azure.servicebus.TransportType
        :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
         Additionally the following keys may also be present: `'username', 'password'`.
        :rtype: ~azure.servicebus.aio.ServiceBusSender

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START create_servicebus_sender_from_conn_str_async]
                :end-before: [END create_servicebus_sender_from_conn_str_async]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the ServiceBusSender from connection string.

        """
        constructor_args = cls._from_connection_string(
            conn_str,
            **kwargs
        )
        return cls(**constructor_args)

    async def send(self, message):
        # type: (Union[Message, BatchMessage]) -> None
        """Sends message and blocks until acknowledgement is received or operation times out.

        :param message: The ServiceBus message to be sent.
        :type message: ~azure.servicebus.Message or ~azure.servicebus.BatchMessage
        :rtype: None
        :raises: ~azure.servicebus.common.errors.MessageSendFailed if the message fails to
         send or ~azure.servicebus.common.errors.OperationTimeoutError if sending times out.

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START send_async]
                :end-before: [END send_async]
                :language: python
                :dedent: 4
                :caption: Send message.

        """
        if isinstance(message, BatchMessage):
            if len(message) == 0:
                raise MessageError("A BatchMessage must have at least one Message")
        elif not isinstance(message, Message):
            raise TypeError("message must be of type Message or BatchMessage")
        await self._do_retryable_operation(
            self._send,
            message=message,
            require_timeout=True,
            require_last_exception=True
        )

    async def create_batch(self, max_size_in_bytes=None):
        # type: (int) -> BatchMessage
        """Create a BatchMessage object with the max size of all content being constrained by max_size_in_bytes.
        The max_size should be no greater than the max allowed message size defined by the service.

        :param int max_size_in_bytes: The maximum size of bytes data that a BatchMessage object can hold. By
         default, the value is determined by your Service Bus tier.
        :rtype: ~azure.servicebus.BatchMessage

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START create_batch_async]
                :end-before: [END create_batch_async]
                :language: python
                :dedent: 4
                :caption: Create BatchMessage object within limited size

        """
        if not self._max_message_size_on_link:
            await self._open_with_retry()

        if max_size_in_bytes and max_size_in_bytes > self._max_message_size_on_link:
            raise ValueError(
                "Max message size: {} is too large, acceptable max batch size is: {} bytes.".format(
                    max_size_in_bytes, self._max_message_size_on_link
                )
            )

        return BatchMessage(
            max_size_in_bytes=(max_size_in_bytes or self._max_message_size_on_link)
        )
