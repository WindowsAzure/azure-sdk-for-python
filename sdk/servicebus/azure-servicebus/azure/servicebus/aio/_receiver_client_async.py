# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import asyncio
import collections
import functools
import logging
from typing import Any, TYPE_CHECKING, List

from uamqp import ReceiveClientAsync, types

from ._client_base_async import ClientBaseAsync
from .async_message import Message as MessageAsync, DeferredMessage
from .._receiver_client import ReceiverMixin
from ..common.utils import create_properties
from ..common.constants import (
    REQUEST_RESPONSE_UPDATE_DISPOSTION_OPERATION,
    REQUEST_RESPONSE_RECEIVE_BY_SEQUENCE_NUMBER
)
from ..common import mgmt_handlers

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

_LOGGER = logging.getLogger(__name__)


class ServiceBusReceiverClient(collections.abc.AsyncIterator, ClientBaseAsync, ReceiverMixin):
    def __init__(
        self,
        fully_qualified_namespace: str,
        credential: "TokenCredential",
        **kwargs: Any
    ):
        if kwargs.get("from_connection_str", False):
            super(ServiceBusReceiverClient, self).__init__(
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

            super(ServiceBusReceiverClient, self).__init__(
                fully_qualified_namespace=fully_qualified_namespace,
                credential=credential,
                entity_name=entity_name,
                **kwargs
            )
        self._create_attribute(**kwargs)

    async def __anext__(self):
        while True:
            try:
                await self._open()
                uamqp_message = await self._message_iter.__anext__()
                message = self._build_message(uamqp_message, MessageAsync)
                return message
            except StopAsyncIteration:
                await self.close()
                raise
            except Exception as e:  # pylint: disable=broad-except
                await self._handle_exception(e)

    def _create_handler(self, auth):
        properties = create_properties()
        if not self._session_id:
            self._handler = ReceiveClientAsync(
                self._entity_uri,
                auth=auth,
                debug=self._config.logging_enable,
                properties=properties,
                error_policy=self._error_policy,
                client_name=self._name,
                auto_complete=False,
                encoding=self._config.encoding,
                receive_settle_mode=self._mode.value
            )
        else:
            self._handler = ReceiveClientAsync(
                self._get_source_for_session_entity(),
                auth=auth,
                debug=self._config.logging_enable,
                properties=properties,
                error_policy=self._error_policy,
                client_name=self._name,
                on_attach=self._on_attach_for_session_entity,
                auto_complete=False,
                encoding=self._config.encoding,
                receive_settle_mode=self._mode.value
            )

    async def _open(self):
        if self._running:
            return
        if self._handler:
            await self._handler.close_async()
        try:
            auth = await self._create_auth()
            self._create_handler(auth)
            await self._handler.open_async()
            self._message_iter = self._handler.receive_messages_iter_async()
            while not await self._handler.client_ready_async():
                await asyncio.sleep(0.05)
        except Exception as e:  # pylint: disable=broad-except
            try:
                await self._handle_exception(e)
            except Exception:
                self.running = False
                raise
        self._running = True

    async def _receive(self, max_batch_size=None, timeout=None):
        await self._open()
        wrapped_batch = []
        max_batch_size = max_batch_size or self._handler._prefetch  # pylint: disable=protected-access

        timeout_ms = 1000 * timeout if timeout else 0
        batch = await self._handler.receive_message_batch_async(
            max_batch_size=max_batch_size,
            timeout=timeout_ms)
        for received in batch:
            message = self._build_message(received, MessageAsync)
            wrapped_batch.append(message)

        return wrapped_batch

    async def _settle_deferred(self, settlement, lock_tokens, dead_letter_details=None):
        message = {
            'disposition-status': settlement,
            'lock-tokens': types.AMQPArray(lock_tokens)}
        if dead_letter_details:
            message.update(dead_letter_details)
        return await self._mgmt_request_response(
            REQUEST_RESPONSE_UPDATE_DISPOSTION_OPERATION,
            message,
            mgmt_handlers.default)

    @classmethod
    def from_connection_string(
        cls,
        conn_str: str,
        **kwargs: Any,
    ) -> "ServiceBusReceiverClient":
        constructor_args = cls._from_connection_string(
            conn_str,
            **kwargs
        )
        if kwargs.get("queue_name") and kwargs.get("subscription_name"):
            raise ValueError("Queue entity does not have subscription.")

        if kwargs.get("topic_name") and not kwargs.get("subscription_name"):
            raise ValueError("Subscription name is missing for the topic. Please specify subscription_name.")
        return cls(**constructor_args)

    async def close(self, exception=None):
        if not self._running:
            return
        self._running = False
        await super(ServiceBusReceiverClient, self).close(exception=exception)

    async def receive(self, max_batch_size=None, timeout=None):
        # type: (int, float) -> List[ReceivedMessage]
        return await self._do_retryable_operation(
            self._receive,
            max_batch_size=max_batch_size,
            timeout=timeout,
            require_timeout=True
        )

    async def receive_deferred_messages(self, sequence_numbers):
        # type: (List[int]) -> List[DeferredMessage]
        if not sequence_numbers:
            raise ValueError("At least one sequence number must be specified.")
        await self._open()
        try:
            receive_mode = self._mode.value.value
        except AttributeError:
            receive_mode = int(self._mode)
        message = {
            'sequence-numbers': types.AMQPArray([types.AMQPLong(s) for s in sequence_numbers]),
            'receiver-settle-mode': types.AMQPuInt(receive_mode),
            'session-id': self._session_id
        }
        handler = functools.partial(mgmt_handlers.deferred_message_op, mode=receive_mode, message_type=DeferredMessage)
        messages = await self._mgmt_request_response(
            REQUEST_RESPONSE_RECEIVE_BY_SEQUENCE_NUMBER,
            message,
            handler)
        for m in messages:
            m._receiver = self  # pylint: disable=protected-access
        return messages
