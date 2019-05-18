# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from __future__ import unicode_literals

import logging
import datetime
import sys
import uuid
import time
import functools
try:
    from urlparse import urlparse
    from urllib import unquote_plus, urlencode, quote_plus
except ImportError:
    from urllib.parse import urlparse, unquote_plus, urlencode, quote_plus

import uamqp
from uamqp import Message
from uamqp import authentication
from uamqp import constants

from azure.eventhub import __version__
from azure.eventhub.sender import Sender
from azure.eventhub.receiver import Receiver
from azure.eventhub.common import EventHubError, parse_sas_token
from .client_abstract import EventHubClientAbstract


log = logging.getLogger(__name__)


class EventHubClient(EventHubClientAbstract):
    """
    The EventHubClient class defines a high level interface for sending
    events to and receiving events from the Azure Event Hubs service.

    Example:
        .. literalinclude:: ../examples/test_examples_eventhub.py
            :start-after: [START create_eventhub_client]
            :end-before: [END create_eventhub_client]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the Event Hub client

    """

    def _create_auth(self, username=None, password=None):
        """
        Create an ~uamqp.authentication.SASTokenAuth instance to authenticate
        the session.

        :param username: The name of the shared access policy.
        :type username: str
        :param password: The shared access key.
        :type password: str
        """
        http_proxy = self.config.http_proxy
        transport_type = self.config.transport_type
        auth_timeout = self.config.auth_timeout
        if self.aad_credential and self.sas_token:
            raise EventHubError("Can't have both sas_token and aad credential")

        elif self.aad_credential:
            get_jwt_token = functools.partial(self.aad_credential.get_token, ['https://eventhubs.azure.net//.default'])
            return authentication.JWTTokenAuth(self.auth_uri, self.auth_uri,
                                               get_jwt_token, http_proxy=http_proxy,
                                               transport_type=transport_type)
        elif self.sas_token:
            token = self.sas_token() if callable(self.sas_token) else self.sas_token
            try:
                expiry = int(parse_sas_token(token)['se'])
            except (KeyError, TypeError, IndexError):
                raise ValueError("Supplied SAS token has no valid expiry value.")
            return authentication.SASTokenAuth(
                self.auth_uri, self.auth_uri, token,
                expires_at=expiry,
                timeout=auth_timeout,
                http_proxy=http_proxy,
                transport_type=transport_type)

        username = username or self._auth_config['username']
        password = password or self._auth_config['password']
        if "@sas.root" in username:
            return authentication.SASLPlain(
                self.address.hostname, username, password, http_proxy=http_proxy, transport_type=transport_type)
        return authentication.SASTokenAuth.from_shared_access_key(
            self.auth_uri, username, password, timeout=auth_timeout, http_proxy=http_proxy, transport_type=transport_type)

    def get_eventhub_information(self):
        """
        Get details on the specified EventHub.
        Keys in the details dictionary include:

            -'name'
            -'type'
            -'created_at'
            -'partition_count'
            -'partition_ids'

        :rtype: dict
        """
        alt_creds = {
            "username": self._auth_config.get("iot_username"),
            "password": self._auth_config.get("iot_password")}
        try:
            mgmt_auth = self._create_auth(**alt_creds)
            mgmt_client = uamqp.AMQPClient(self.mgmt_target, auth=mgmt_auth, debug=self.debug)
            mgmt_client.open()
            mgmt_msg = Message(application_properties={'name': self.eh_name})
            response = mgmt_client.mgmt_request(
                mgmt_msg,
                constants.READ_OPERATION,
                op_type=b'com.microsoft:eventhub',
                status_code_field=b'status-code',
                description_fields=b'status-description')
            eh_info = response.get_data()
            output = {}
            if eh_info:
                output['name'] = eh_info[b'name'].decode('utf-8')
                output['type'] = eh_info[b'type'].decode('utf-8')
                output['created_at'] = datetime.datetime.fromtimestamp(float(eh_info[b'created_at'])/1000)
                output['partition_count'] = eh_info[b'partition_count']
                output['partition_ids'] = [p.decode('utf-8') for p in eh_info[b'partition_ids']]
            return output
        finally:
            mgmt_client.close()

    def create_receiver(
            self, consumer_group, partition, offset=None, epoch=None, operation=None,
            prefetch=None,
            keep_alive=None,
            auto_reconnect=None,
    ):
        """
        Add a receiver to the client for a particular consumer group and partition.

        :param consumer_group: The name of the consumer group.
        :type consumer_group: str
        :param partition: The ID of the partition.
        :type partition: str
        :param offset: The offset from which to start receiving.
        :type offset: ~azure.eventhub.common.Offset
        :param prefetch: The message prefetch count of the receiver. Default is 300.
        :type prefetch: int
        :operation: An optional operation to be appended to the hostname in the source URL.
         The value must start with `/` character.
        :type operation: str
        :rtype: ~azure.eventhub.receiver.Receiver

        Example:
            .. literalinclude:: ../examples/test_examples_eventhub.py
                :start-after: [START create_eventhub_client_receiver]
                :end-before: [END create_eventhub_client_receiver]
                :language: python
                :dedent: 4
                :caption: Add a receiver to the client for a particular consumer group and partition.

        """
        keep_alive = self.config.keep_alive if keep_alive is None else keep_alive
        auto_reconnect = self.config.auto_reconnect if auto_reconnect is None else auto_reconnect
        prefetch = self.config.prefetch if prefetch is None else prefetch

        path = self.address.path + operation if operation else self.address.path
        source_url = "amqps://{}{}/ConsumerGroups/{}/Partitions/{}".format(
            self.address.hostname, path, consumer_group, partition)
        handler = Receiver(
            self, source_url, offset=offset, epoch=epoch, prefetch=prefetch, keep_alive=keep_alive, auto_reconnect=auto_reconnect)
        self.clients.append(handler)
        return handler

    def create_epoch_receiver(
            self, consumer_group, partition, epoch, prefetch=300,
            operation=None):
        return self.create_receiver(consumer_group, partition, epoch=epoch, prefetch=prefetch, operation=operation)

    def create_sender(self, partition=None, operation=None, send_timeout=None, keep_alive=None, auto_reconnect=None):
        """
        Add a sender to the client to send EventData object to an EventHub.

        :param partition: Optionally specify a particular partition to send to.
         If omitted, the events will be distributed to available partitions via
         round-robin.
        :type parition: str
        :operation: An optional operation to be appended to the hostname in the target URL.
         The value must start with `/` character.
        :type operation: str
        :param send_timeout: The timeout in seconds for an individual event to be sent from the time that it is
         queued. Default value is 60 seconds. If set to 0, there will be no timeout.
        :type send_timeout: int
        :param keep_alive: The time interval in seconds between pinging the connection to keep it alive during
         periods of inactivity. The default value is 30 seconds. If set to `None`, the connection will not
         be pinged.
        :type keep_alive: int
        :param auto_reconnect: Whether to automatically reconnect the sender if a retryable error occurs.
         Default value is `True`.
        :rtype: ~azure.eventhub.sender.Sender

        Example:
            .. literalinclude:: ../examples/test_examples_eventhub.py
                :start-after: [START create_eventhub_client_sender]
                :end-before: [END create_eventhub_client_sender]
                :language: python
                :dedent: 4
                :caption: Add a sender to the client to send EventData object to an EventHub.

        """
        target = "amqps://{}{}".format(self.address.hostname, self.address.path)
        if operation:
            target = target + operation
        send_timeout = self.config.send_timeout if send_timeout is None else send_timeout
        keep_alive = self.config.keep_alive if keep_alive is None else keep_alive
        auto_reconnect = self.config.auto_reconnect if auto_reconnect is None else auto_reconnect

        handler = Sender(
            self, target, partition=partition, send_timeout=send_timeout, keep_alive=keep_alive, auto_reconnect=auto_reconnect)
        self.clients.append(handler)
        return handler
