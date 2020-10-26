# ------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -------------------------------------------------------------------------

import sys
import datetime
import logging
import functools
import platform
from typing import Optional, Dict, Tuple, Iterable
from contextlib import contextmanager
from msrest.serialization import UTC

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from uamqp import authentication, types

from azure.core.settings import settings
from azure.core.tracing import SpanKind

from .._version import VERSION
from .constants import (
    JWT_TOKEN_SCOPE,
    TOKEN_TYPE_JWT,
    TOKEN_TYPE_SASTOKEN,
    DEAD_LETTER_QUEUE_SUFFIX,
    TRANSFER_DEAD_LETTER_QUEUE_SUFFIX,
    USER_AGENT_PREFIX,
    SPAN_NAME_SEND,
    SPAN_NAME_MESSAGE,
    TRACE_PARENT_PROPERTY,
    TRACE_NAMESPACE,
    TRACE_NAMESPACE_PROPERTY,
    TRACE_PROPERTY_ENCODING,
    TRACE_ENQUEUED_TIME_PROPERTY,
    SPAN_ENQUEUED_TIME_PROPERTY
)

_log = logging.getLogger(__name__)


def utc_from_timestamp(timestamp):
    return datetime.datetime.fromtimestamp(timestamp, tz=UTC())


def utc_now():
    return datetime.datetime.now(UTC())


def build_uri(address, entity):
    parsed = urlparse(address)
    if parsed.path:
        return address
    if not entity:
        raise ValueError("No Service Bus entity specified")
    address += "/" + str(entity)
    return address


def create_properties(user_agent=None):
    # type: (Optional[str]) -> Dict[types.AMQPSymbol, str]
    """
    Format the properties with which to instantiate the connection.
    This acts like a user agent over HTTP.

    :param str user_agent: If specified,
    this will be added in front of the built-in user agent string.

    :rtype: dict
    """
    properties = {}
    properties[types.AMQPSymbol("product")] = USER_AGENT_PREFIX
    properties[types.AMQPSymbol("version")] = VERSION
    framework = "Python/{}.{}.{}".format(
        sys.version_info[0], sys.version_info[1], sys.version_info[2]
    )
    properties[types.AMQPSymbol("framework")] = framework
    platform_str = platform.platform()
    properties[types.AMQPSymbol("platform")] = platform_str

    final_user_agent = "{}/{} {} ({})".format(
        USER_AGENT_PREFIX, VERSION, framework, platform_str
    )
    if user_agent:
        final_user_agent = "{} {}".format(user_agent, final_user_agent)

    properties[types.AMQPSymbol("user-agent")] = final_user_agent
    return properties


def renewable_start_time(renewable):
    try:
        return renewable._received_timestamp_utc  # pylint: disable=protected-access
    except AttributeError:
        pass
    try:
        return renewable._session_start  # pylint: disable=protected-access
    except AttributeError:
        raise TypeError("Registered object is not renewable.")


def create_authentication(client):
    # pylint: disable=protected-access
    try:
        # ignore mypy's warning because token_type is Optional
        token_type = client._credential.token_type  # type: ignore
    except AttributeError:
        token_type = TOKEN_TYPE_JWT
    if token_type == TOKEN_TYPE_SASTOKEN:
        auth = authentication.JWTTokenAuth(
            client._auth_uri,
            client._auth_uri,
            functools.partial(client._credential.get_token, client._auth_uri),
            token_type=token_type,
            timeout=client._config.auth_timeout,
            http_proxy=client._config.http_proxy,
            transport_type=client._config.transport_type,
        )
        auth.update_token()
        return auth
    return authentication.JWTTokenAuth(
        client._auth_uri,
        client._auth_uri,
        functools.partial(client._credential.get_token, JWT_TOKEN_SCOPE),
        token_type=token_type,
        timeout=client._config.auth_timeout,
        http_proxy=client._config.http_proxy,
        transport_type=client._config.transport_type,
    )


def generate_dead_letter_entity_name(
    queue_name=None, topic_name=None, subscription_name=None, transfer_deadletter=False
):
    entity_name = (
        queue_name
        if queue_name
        else (topic_name + "/Subscriptions/" + subscription_name)
    )
    entity_name = "{}{}".format(
        entity_name,
        TRANSFER_DEAD_LETTER_QUEUE_SUFFIX
        if transfer_deadletter
        else DEAD_LETTER_QUEUE_SUFFIX,
    )

    return entity_name


def transform_messages_to_sendable_if_needed(messages):
    """
    This method is to convert single/multiple received messages
    to sendable messages to enable message resending.
    """
    # pylint: disable=protected-access
    try:
        msgs_to_return = []
        for each in messages:
            try:
                msgs_to_return.append(each._to_outgoing_message())
            except AttributeError:
                msgs_to_return.append(each)
        return msgs_to_return
    except TypeError:
        try:
            return messages._to_outgoing_message()
        except AttributeError:
            return messages


@contextmanager
def send_trace_context_manager(span_name=SPAN_NAME_SEND):
    span_impl_type = (
        settings.tracing_implementation()
    )  # type: Type[AbstractSpan]

    if span_impl_type is not None:
        with span_impl_type(name=span_name) as child:
            child.kind = SpanKind.CLIENT
            yield child
    else:
        yield None


def add_link_to_send(message, send_span):
    """Add Diagnostic-Id from message to span as link.
    """
    try:
        if send_span and message.message.application_properties:
            traceparent = message.message.application_properties \
                .get(TRACE_PARENT_PROPERTY, "") \
                .decode(TRACE_PROPERTY_ENCODING)
            if traceparent:
                send_span.link(traceparent)
    except Exception as exp:  # pylint:disable=broad-except
        _log.warning("add_link_to_send had an exception %r", exp)


def trace_message(message, parent_span=None):
    # type: (Message, Optional[AbstractSpan]) -> None
    """Add tracing information to this message.
    Will open and close a "Azure.Servicebus.message" span, and
    add the "DiagnosticId" as app properties of the message.
    """
    try:
        span_impl_type = settings.tracing_implementation()  # type: Type[AbstractSpan]
        if span_impl_type is not None:
            current_span = parent_span or span_impl_type(
                span_impl_type.get_current_span()
            )
            with current_span.span(name=SPAN_NAME_MESSAGE) as message_span:
                message_span.kind = SpanKind.PRODUCER
                message_span.add_attribute(TRACE_NAMESPACE_PROPERTY, TRACE_NAMESPACE)
                # TODO: Remove intermediary message; this is standin while this var is being renamed in a concurrent PR
                if not message.message.application_properties:
                    message.message.application_properties = dict()
                message.message.application_properties.setdefault(
                    TRACE_PARENT_PROPERTY, message_span.get_trace_parent().encode(TRACE_PROPERTY_ENCODING)
                )
    except Exception as exp:  # pylint:disable=broad-except
        _log.warning("trace_message had an exception %r", exp)


def trace_link_message(messages, parent_span=None):
    # type: (Union[Message, Iterable[Message]], Optional[AbstractSpan]) -> None
    """Link the current message(s) to current span or provided parent span.
    Will extract DiagnosticId if available.
    """
    trace_messages = messages if isinstance(messages, Iterable) else (messages,)  # pylint:disable=isinstance-second-argument-not-valid-type
    try:  # pylint:disable=too-many-nested-blocks
        span_impl_type = settings.tracing_implementation()  # type: Type[AbstractSpan]
        if span_impl_type is not None:
            current_span = parent_span or span_impl_type(
                span_impl_type.get_current_span()
            )
            if current_span:
                for message in trace_messages:  # type: ignore
                    if message.message.application_properties:
                        traceparent = message.message.application_properties \
                            .get(TRACE_PARENT_PROPERTY, "") \
                            .decode(TRACE_PROPERTY_ENCODING)
                        if traceparent:
                            current_span.link(
                                traceparent,
                                attributes={SPAN_ENQUEUED_TIME_PROPERTY: \
                                    message.message.annotations.get(TRACE_ENQUEUED_TIME_PROPERTY)}
                            )
    except Exception as exp:  # pylint:disable=broad-except
        _log.warning("trace_link_message had an exception %r", exp)
