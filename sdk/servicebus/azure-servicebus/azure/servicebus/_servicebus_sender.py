# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import logging
import time
import uuid
from typing import Any, TYPE_CHECKING, Union, List, Optional

import uamqp
from uamqp import SendClient, types
from uamqp.authentication.common import AMQPAuth

from ._base_handler import BaseHandler, ServiceBusSharedKeyCredential, _convert_connection_string_to_kwargs
from ._common import mgmt_handlers
from ._common.message import Message, BatchMessage
from .exceptions import (
    OperationTimeoutError,
    _ServiceBusErrorPolicy,
    )
from ._common.utils import create_authentication, transform_messages_to_sendable_if_needed
from ._common.constants import (
    REQUEST_RESPONSE_CANCEL_SCHEDULED_MESSAGE_OPERATION,
    REQUEST_RESPONSE_SCHEDULE_MESSAGE_OPERATION,
    MGMT_REQUEST_SEQUENCE_NUMBERS,
    MGMT_REQUEST_SESSION_ID,
    MGMT_REQUEST_MESSAGE,
    MGMT_REQUEST_MESSAGES,
    MGMT_REQUEST_MESSAGE_ID,
    MGMT_REQUEST_PARTITION_KEY,
    MGMT_REQUEST_VIA_PARTITION_KEY
)

if TYPE_CHECKING:
    import datetime
    from azure.core.credentials import TokenCredential

_LOGGER = logging.getLogger(__name__)


class SenderMixin(object):
    def _create_attribute(self):
        self._auth_uri = "sb://{}/{}".format(self.fully_qualified_namespace, self._entity_name)
        self._entity_uri = "amqps://{}/{}".format(self.fully_qualified_namespace, self._entity_name)
        self._error_policy = _ServiceBusErrorPolicy(max_retries=self._config.retry_total)
        self._name = "SBSender-{}".format(uuid.uuid4())
        self._max_message_size_on_link = 0
        self.entity_name = self._entity_name

    def _set_msg_timeout(self, timeout=None, last_exception=None):
        if not timeout:
            return
        timeout_time = time.time() + timeout
        remaining_time = timeout_time - time.time()
        if remaining_time <= 0.0:
            if last_exception:
                error = last_exception
            else:
                error = OperationTimeoutError("Send operation timed out")
            _LOGGER.info("%r send operation timed out. (%r)", self._name, error)
            raise error
        self._handler._msg_timeout = remaining_time * 1000  # type: ignore  # pylint: disable=protected-access

    @classmethod
    def _build_schedule_request(cls, schedule_time_utc, *messages):
        request_body = {MGMT_REQUEST_MESSAGES: []}
        for message in messages:
            if not isinstance(message, Message):
                raise ValueError("Scheduling batch messages only supports iterables containing Message Objects."
                                 " Received instead: {}".format(message.__class__.__name__))
            message = transform_messages_to_sendable_if_needed(message)
            message.scheduled_enqueue_time_utc = schedule_time_utc
            message_data = {}
            message_data[MGMT_REQUEST_MESSAGE_ID] = message.message_id
            if message.session_id:
                message_data[MGMT_REQUEST_SESSION_ID] = message.session_id
            if message.partition_key:
                message_data[MGMT_REQUEST_PARTITION_KEY] = message.partition_key
            if message.via_partition_key:
                message_data[MGMT_REQUEST_VIA_PARTITION_KEY] = message.via_partition_key
            message_data[MGMT_REQUEST_MESSAGE] = bytearray(message.message.encode_message())
            request_body[MGMT_REQUEST_MESSAGES].append(message_data)
        return request_body


class ServiceBusSender(BaseHandler, SenderMixin):
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
    :keyword str user_agent: If specified, this will be added in front of the built-in user agent string.

    .. admonition:: Example:

        .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
            :start-after: [START create_servicebus_sender_sync]
            :end-before: [END create_servicebus_sender_sync]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the ServiceBusSender.

    """
    def __init__(
        self,
        fully_qualified_namespace,
        credential,
        **kwargs
    ):
        # type: (str, TokenCredential, Any) -> None
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
            entity_name = queue_name or topic_name
            if not entity_name:
                raise ValueError("Queue/Topic name is missing. Please specify queue_name/topic_name.")
            super(ServiceBusSender, self).__init__(
                fully_qualified_namespace=fully_qualified_namespace,
                credential=credential,
                entity_name=entity_name,
                **kwargs
            )

        self._max_message_size_on_link = 0
        self._create_attribute()
        self._connection = kwargs.get("connection")

    def _create_handler(self, auth):
        # type: (AMQPAuth) -> None
        self._handler = SendClient(
            self._entity_uri,
            auth=auth,
            debug=self._config.logging_enable,
            properties=self._properties,
            error_policy=self._error_policy,
            client_name=self._name,
            keep_alive_interval=self._config.keep_alive,
            encoding=self._config.encoding
        )

    def _open(self):
        # pylint: disable=protected-access
        if self._running:
            return
        if self._handler:
            self._handler.close()

        auth = None if self._connection else create_authentication(self)
        self._create_handler(auth)
        try:
            self._handler.open(connection=self._connection)
            while not self._handler.client_ready():
                time.sleep(0.05)
            self._running = True
            self._max_message_size_on_link = self._handler.message_handler._link.peer_max_message_size \
                                             or uamqp.constants.MAX_MESSAGE_LENGTH_BYTES
        except:
            self.close()
            raise

    def _send(self, message, timeout=None, last_exception=None):
        # type: (Message, Optional[float], Exception) -> None
        self._open()
        self._set_msg_timeout(timeout, last_exception)
        self._handler.send_message(message.message)

    def schedule_messages(self, messages, schedule_time_utc):
        # type: (Union[Message, List[Message]], datetime.datetime) -> List[int]
        """Send Message or multiple Messages to be enqueued at a specific time.
        Returns a list of the sequence numbers of the enqueued messages.
        :param messages: The message or list of messages to schedule.
        :type messages: Union[~azure.servicebus.Message, List[~azure.servicebus.Message]]
        :param schedule_time_utc: The utc date and time to enqueue the messages.
        :type schedule_time_utc: ~datetime.datetime
        :rtype: List[int]

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START scheduling_messages]
                :end-before: [END scheduling_messages]
                :language: python
                :dedent: 4
                :caption: Schedule a message to be sent in future
        """
        # pylint: disable=protected-access
        self._open()
        if isinstance(messages, Message):
            request_body = self._build_schedule_request(schedule_time_utc, messages)
        else:
            request_body = self._build_schedule_request(schedule_time_utc, *messages)
        return self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_SCHEDULE_MESSAGE_OPERATION,
            request_body,
            mgmt_handlers.schedule_op
        )

    def cancel_scheduled_messages(self, sequence_numbers):
        # type: (Union[int, List[int]]) -> None
        """
        Cancel one or more messages that have previously been scheduled and are still pending.

        :param sequence_numbers: The sequence numbers of the scheduled messages.
        :type sequence_numbers: int or list[int]
        :rtype: None
        :raises: ~azure.servicebus.exceptions.ServiceBusError if messages cancellation failed due to message already
         cancelled or enqueued.

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START cancel_scheduled_messages]
                :end-before: [END cancel_scheduled_messages]
                :language: python
                :dedent: 4
                :caption: Cancelling messages scheduled to be sent in future
        """
        self._open()
        if isinstance(sequence_numbers, int):
            numbers = [types.AMQPLong(sequence_numbers)]
        else:
            numbers = [types.AMQPLong(s) for s in sequence_numbers]
        request_body = {MGMT_REQUEST_SEQUENCE_NUMBERS: types.AMQPArray(numbers)}
        return self._mgmt_request_response_with_retry(
            REQUEST_RESPONSE_CANCEL_SCHEDULED_MESSAGE_OPERATION,
            request_body,
            mgmt_handlers.default
        )

    @classmethod
    def from_connection_string(
        cls,
        conn_str,
        **kwargs
    ):
        # type: (str, Any) -> ServiceBusSender
        """Create a ServiceBusSender from a connection string.

        :param conn_str: The connection string of a Service Bus.
        :type conn_str: str
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
        :keyword str user_agent: If specified, this will be added in front of the built-in user agent string.

        :rtype: ~azure.servicebus.ServiceBusSender

        :raises ~azure.servicebus.ServiceBusAuthenticationError: Indicates an issue in token/identity validity.
        :raises ~azure.servicebus.ServiceBusAuthorizationError: Indicates an access/rights related failure.

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START create_servicebus_sender_from_conn_str_sync]
                :end-before: [END create_servicebus_sender_from_conn_str_sync]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the ServiceBusSender from connection string.

        """
        constructor_args = _convert_connection_string_to_kwargs(
            conn_str,
            ServiceBusSharedKeyCredential,
            **kwargs
        )
        return cls(**constructor_args)

    def send_messages(self, message):
        # type: (Union[Message, BatchMessage, List[Message]]) -> None
        """Sends message and blocks until acknowledgement is received or operation times out.

        If a list of messages was provided, attempts to send them as a single batch, throwing a
        `ValueError` if they cannot fit in a single batch.

        :param message: The ServiceBus message to be sent.
        :type message: ~azure.servicebus.Message or ~azure.servicebus.BatchMessage or list[~azure.servicebus.Message]
        :rtype: None
        :raises:
                :class: ~azure.servicebus.exceptions.OperationTimeoutError if sending times out.
                :class: ~azure.servicebus.exceptions.MessageContentTooLarge if the size of the message is over
                  service bus frame size limit.
                :class: ~azure.servicebus.exceptions.MessageSendFailed if the message fails to send
                :class: ~azure.servicebus.exceptions.ServiceBusError when other errors happen such as connection
                 error, authentication error, and any unexpected errors.
                 It's also the top-level root class of above errors.

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START send_sync]
                :end-before: [END send_sync]
                :language: python
                :dedent: 4
                :caption: Send message.

        """
        message = transform_messages_to_sendable_if_needed(message)
        try:
            batch = self.create_batch()
            batch._from_list(message)  # pylint: disable=protected-access
            message = batch
        except TypeError:  # Message was not a list or generator.
            pass
        if isinstance(message, BatchMessage) and len(message) == 0:  # pylint: disable=len-as-condition
            raise ValueError("A BatchMessage or list of Message must have at least one Message")
        if not isinstance(message, BatchMessage) and not isinstance(message, Message):
            raise TypeError("Can only send azure.servicebus.<BatchMessage,Message> or lists of Messages.")

        self._do_retryable_operation(
            self._send,
            message=message,
            require_timeout=True,
            require_last_exception=True
        )

    def create_batch(self, max_size_in_bytes=None):
        # type: (int) -> BatchMessage
        """Create a BatchMessage object with the max size of all content being constrained by max_size_in_bytes.
        The max_size should be no greater than the max allowed message size defined by the service.

        :param int max_size_in_bytes: The maximum size of bytes data that a BatchMessage object can hold. By
         default, the value is determined by your Service Bus tier.
        :rtype: ~azure.servicebus.BatchMessage

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START create_batch_sync]
                :end-before: [END create_batch_sync]
                :language: python
                :dedent: 4
                :caption: Create BatchMessage object within limited size

        """
        if not self._max_message_size_on_link:
            self._open_with_retry()

        if max_size_in_bytes and max_size_in_bytes > self._max_message_size_on_link:
            raise ValueError(
                "Max message size: {} is too large, acceptable max batch size is: {} bytes.".format(
                    max_size_in_bytes, self._max_message_size_on_link
                )
            )

        return BatchMessage(
            max_size_in_bytes=(max_size_in_bytes or self._max_message_size_on_link)
        )
