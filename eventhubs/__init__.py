# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
The module provides a client to connect to Azure Event Hubs.

"""

# pylint: disable=line-too-long
# pylint: disable=W0613
# pylint: disable=W0702

import logging
import datetime

from proton import DELEGATED, Url, timestamp, generate_uuid, Message
from proton.reactor import dispatch, Container, Selector
from proton.handlers import Handler, EndpointStateHandler
from proton.handlers import IncomingMessageHandler
from proton.handlers import CFlowController, OutgoingMessageHandler
from eventhubs._impl import ReceiverHandler, OffsetUtil

class EventHubClient(Container):
    """
    The L{EventHubClient} class defines a high level interface for sending
    events to and receiving events from the Azure Event Hubs service.
    """
    def __init__(self, address=None, **kwargs):
        """
        Constructs a new L{EventHubClient} with the given address Url.
        """
        if not address:
            super(EventHubClient, self).__init__(**kwargs)
        else:
            super(EventHubClient, self).__init__(self, **kwargs)
            self.allow_insecure_mechs = False
            self.allowed_mechs = 'PLAIN MSCBS'
            self.container_id = "ehpy-" + str(generate_uuid())[:8]
            self.address = Url(address)
            self.shared_connection = None
            self.shared_session = None
            self.clients = []

    def subscribe(self, handler, consumer_group, partition, offset=None, prefetch=300):
        """
        Subscribes to an Event Hub partition to receive events.

        @param handler: handler to process the received event data. It must
        define an 'on_event_data' method to handle incoming events.

        @param consumer_group: the consumer group the receiver belongs to.

        @param partition: the id of the event hub partition.

        @param offset: the L{Offset} to receive events.

        @param prefetch: the number of events that will be proactively prefetched
        by the library into a local buffer queue.

        """
        _source = "%s/ConsumerGroups/%s/Partitions/%s" % (self.address.path, consumer_group, partition)
        _selector = OffsetUtil.selector(offset.value, offset.inclusive)
        _receiver = ReceiverHandler(handler, _source, EventData.create, _selector, prefetch)
        self.clients.append(_receiver)
        return self

    def publish(self, handler, partition=None):
        """
        Publishes to the event hub or one of its partitions.
        """
        raise NotImplementedError("Publish is under development")

    def session(self, context):
        if not self.shared_session:
            self.shared_session = context.session()
            self.shared_session.open()
        return self.shared_session

    def on_reactor_init(self, event):
        if not self.shared_connection:
            logging.info("%s: client starts address=%s", self.container_id, self.address)
            self.shared_connection = self.connect(self.address, reconnect=False, handler=self)
            self.shared_connection.__setattr__("_session_policy", self)
        for client in self.clients:
            client.start(self)

    def on_client_event(self, event):
        dispatch(event.client, event.typename, event.subject)

    def on_connection_local_open(self, event):
        logging.info("%s: connection local open", event.connection.container)

    def on_connection_remote_open(self, event):
        logging.info("%s: connection remote open %s", self.container_id, event.connection.remote_container)

    def on_session_local_open(self, event):
        logging.info("%s: session local open", self.container_id)

    def on_session_remote_open(self, event):
        logging.info("%s: session remote open", self.container_id)

    def on_connection_remote_close(self, event):
        if EndpointStateHandler.is_local_closed(self.shared_connection):
            return DELEGATED
        condition = self.shared_connection.remote_condition
        if condition:
            logging.error("%s: connection closed by peer %s:%s %s",
                          self.container_id,
                          condition.name,
                          condition.description,
                          self.shared_connection.remote_container)
        else:
            logging.error("%s: connection closed by peer %s",
                          self.container_id,
                          self.shared_connection.remote_container)
        self._free_clients()
        self._free_session()
        self._free_connection()
        self.on_reactor_init(None)

    def on_session_remote_close(self, event):
        if EndpointStateHandler.is_local_closed(event.session):
            return DELEGATED
        condition = self.shared_session.remote_condition
        if condition:
            logging.error("%s: session close %s:%s %s",
                          self.container_id,
                          condition.name,
                          condition.description,
                          self.shared_connection.remote_container)
        else:
            logging.error("%s, session close %s",
                          self.container_id,
                          self.shared_connection.remote_container)
        self._free_clients()
        self._free_session()
        self.schedule(3.0, self)

    def on_transport_closed(self, event):
        logging.error("%s: transport close", self.container_id)
        if self.shared_connection and self.shared_connection.__eq__(event.connection):
            self._free_clients()
            self._free_session()
            self._free_connection()
            self.on_reactor_init(None)

    def on_timer_task(self, event):
        self.on_reactor_init(None)

    def _free_connection(self):
        if self.shared_connection:
            self.shared_connection.__delattr__("_session_policy")
            self.shared_connection.close()
            self.shared_connection.free()
            self.shared_connection = None

    def _free_session(self):
        if self.shared_session:
            self.shared_session.close()
            self.shared_session.free()
            self.shared_session = None

    def _free_clients(self):
        for client in self.clients:
            client.stop()

class EventData(object):
    """
    The L{EventData} class is a holder of event content.
    """

    PROP_SEQ_NUMBER = "x-opt-sequence-number"
    PROP_OFFSET = "x-opt-offset"
    PROP_PARTITION_KEY = "x-opt-partition-key"

    def __init__(self, body=None):
        """
        @param kwargs: name/value pairs in properties.
        """
        self.message = Message(body)

    @property
    def sequence_number(self):
        """
        Return the sequence number of the event data object.
        """
        return self.message.annotations[EventData.PROP_SEQ_NUMBER]

    @property
    def offset(self):
        """
        Return the offset of the event data object.
        """
        return self.message.annotations[EventData.PROP_OFFSET]

    def _get_partition_key(self):
        return self.message.annotations[EventData.PROP_PARTITION_KEY]

    def _set_partition_key(self, value):
        self.message.annotations[EventData.PROP_PARTITION_KEY] = value

    partition_key = property(_get_partition_key, _set_partition_key, doc="""
        Gets or sets the partition key of the event data object.
        """)

    @property
    def properties(self):
        """Application defined properties (dict)."""
        return self.message.properties

    @property
    def body(self):
        """Return the body of the event data object."""
        return self.message.body

    @classmethod
    def create(cls, message):
        """Creates an event data object from an AMQP message."""
        _event = EventData()
        _event.message = message
        return _event

class Offset(object):
    """
    The offset (position or timestamp) where a receiver starts.
    """
    def __init__(self, value, inclusive=False):
        self.value = value
        self.inclusive = inclusive
