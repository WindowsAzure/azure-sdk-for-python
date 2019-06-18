# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from __future__ import unicode_literals

import logging
import sys
import uuid
import time
import functools
from abc import abstractmethod
try:
    from urlparse import urlparse
    from urllib import unquote_plus, urlencode, quote_plus
except ImportError:
    from urllib.parse import urlparse, unquote_plus, urlencode, quote_plus


from azure.eventhub import __version__
from azure.eventhub.configuration import Configuration
from azure.eventhub import constants
from .common import EventHubSharedKeyCredential, _Address

log = logging.getLogger(__name__)


def _parse_conn_str(conn_str):
    endpoint = None
    shared_access_key_name = None
    shared_access_key = None
    entity_path = None
    for element in conn_str.split(';'):
        key, _, value = element.partition('=')
        if key.lower() == 'endpoint':
            endpoint = value.rstrip('/')
        elif key.lower() == 'hostname':
            endpoint = value.rstrip('/')
        elif key.lower() == 'sharedaccesskeyname':
            shared_access_key_name = value
        elif key.lower() == 'sharedaccesskey':
            shared_access_key = value
        elif key.lower() == 'entitypath':
            entity_path = value
    if not all([endpoint, shared_access_key_name, shared_access_key]):
        raise ValueError("Invalid connection string")
    return endpoint, shared_access_key_name, shared_access_key, entity_path


def _generate_sas_token(uri, policy, key, expiry=None):
    """Create a shared access signiture token as a string literal.
    :returns: SAS token as string literal.
    :rtype: str
    """
    from base64 import b64encode, b64decode
    from hashlib import sha256
    from hmac import HMAC
    if not expiry:
        expiry = time.time() + 3600  # Default to 1 hour.
    encoded_uri = quote_plus(uri)
    ttl = int(expiry)
    sign_key = '%s\n%d' % (encoded_uri, ttl)
    signature = b64encode(HMAC(b64decode(key), sign_key.encode('utf-8'), sha256).digest())
    result = {
        'sr': uri,
        'sig': signature,
        'se': str(ttl)}
    if policy:
        result['skn'] = policy
    return 'SharedAccessSignature ' + urlencode(result)


def _build_uri(address, entity):
    parsed = urlparse(address)
    if parsed.path:
        return address
    if not entity:
        raise ValueError("No EventHub specified")
    address += "/" + str(entity)
    return address


class EventHubClientAbstract(object):
    """
    The EventHubClientAbstract class defines a high level interface for sending
    events to and receiving events from the Azure Event Hubs service.
    """

    def __init__(self, host, event_hub_path, credential, **kwargs):
        """
        Constructs a new EventHubClient.

        :param host: The hostname URI string of the the Event Hub.
        :type host: str
        :param event_hub_path: The path/name of the Event Hub
        :type event_hub_path: str
        :param network_tracing: Whether to output network trace logs to the logger. Default
         is `False`.
        :type network_tracing: bool
        :param credential: The credential object used for authentication which implements particular interface
         of getting tokens. It accepts ~azure.eventhub.EventHubSharedKeyCredential,
         ~azure.eventhub.EventHubSASTokenCredential, credential objects generated by the azure-identity library and
         objects that implement get token interface.
        :param http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: 'proxy_hostname' (str value) and 'proxy_port' (int value).
         Additionally the following keys may also be present: 'username', 'password'.
        :type http_proxy: dict[str, Any]
        :param auth_timeout: The time in seconds to wait for a token to be authorized by the service.
         The default value is 60 seconds. If set to 0, no timeout will be enforced from the client.
        :type auth_timeout: int
        :param user_agent: The user agent that needs to be appended to the built in user agent string.
        :type user_agent: str
        :param max_retries: The max number of attempts to redo the failed operation when an error happened. Default
         value is 3.
        :type max_retries: int
        :param transport_type: The transport protocol type - default is ~uamqp.TransportType.Amqp.
         ~uamqp.TransportType.AmqpOverWebsocket is applied when http_proxy is set or the
         transport type is explicitly requested.
        :type transport_type: ~azure.eventhub.TransportType
        :param prefetch: The message prefetch count of the receiver. Default is 300.
        :type prefetch: int
        :param max_batch_size: Receive a batch of events. Batch size will be up to the maximum specified, but
         will return as soon as service returns no new events. Default value is the same as prefetch.
        :type max_batch_size: int
        :param receive_timeout: The timeout time in seconds to receive a batch of events from an Event Hub.
         Default value is 0 seconds.
        :type receive_timeout: int
        :param send_timeout: The timeout in seconds for an individual event to be sent from the time that it is
         queued. Default value is 60 seconds. If set to 0, there will be no timeout.
        :type send_timeout: int
        """
        self.container_id = "eventhub.pysdk-" + str(uuid.uuid4())[:8]
        self.address = _Address()
        self.address.hostname = host
        self.address.path = "/" + event_hub_path if event_hub_path else ""
        self._auth_config = {}
        self.credential = credential
        if isinstance(credential, EventHubSharedKeyCredential):
            self.username = credential.policy
            self.password = credential.key
            self._auth_config['username'] = self.username
            self._auth_config['password'] = self.password

        self.host = host
        self.eh_name = event_hub_path
        self.keep_alive = kwargs.get("keep_alive", 30)
        self.auto_reconnect = kwargs.get("auto_reconnect", True)
        self.mgmt_target = "amqps://{}/{}".format(self.host, self.eh_name)
        self.auth_uri = "sb://{}{}".format(self.address.hostname, self.address.path)
        self.get_auth = functools.partial(self._create_auth)
        self.config = Configuration(**kwargs)
        self.debug = self.config.network_tracing

        log.info("%r: Created the Event Hub client", self.container_id)

    @classmethod
    def from_connection_string(cls, conn_str, event_hub_path=None, **kwargs):
        """Create an EventHubClient from a connection string.

        :param conn_str: The connection string.
        :type conn_str: str
        :param event_hub_path: The path/name of the Event Hub, if the EntityName is
         not included in the connection string.
        :type event_hub_path: str
        :param network_tracing: Whether to output network trace logs to the logger. Default
         is `False`.
        :type network_tracing: bool
        :param http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: 'proxy_hostname' (str value) and 'proxy_port' (int value).
         Additionally the following keys may also be present: 'username', 'password'.
        :type http_proxy: dict[str, Any]
        :param auth_timeout: The time in seconds to wait for a token to be authorized by the service.
         The default value is 60 seconds. If set to 0, no timeout will be enforced from the client.
        :type auth_timeout: float
        :param user_agent: The user agent that needs to be appended to the built in user agent string.
        :type user_agent: str
        :param max_retries: The max number of attempts to redo the failed operation when an error happened. Default
         value is 3.
        :type max_retries: int
        :param transport_type: The transport protocol type - default is ~uamqp.TransportType.Amqp.
         ~uamqp.TransportType.AmqpOverWebsocket is applied when http_proxy is set or the
         transport type is explicitly requested.
        :type transport_type: ~azure.eventhub.TransportType
        :param prefetch: The message prefetch count of the receiver. Default is 300.
        :type prefetch: int
        :param max_batch_size: Receive a batch of events. Batch size will be up to the maximum specified, but
         will return as soon as service returns no new events. Default value is the same as prefetch.
        :type max_batch_size: int
        :param receive_timeout: The timeout time in seconds to receive a batch of events from an Event Hub.
         Default value is 0 seconds.
        :type receive_timeout: float
        :param send_timeout: The timeout in seconds for an individual event to be sent from the time that it is
         queued. Default value is 60 seconds. If set to 0, there will be no timeout.
        :type send_timeout: float

        Example:
            .. literalinclude:: ../examples/test_examples_eventhub.py
                :start-after: [START create_eventhub_client_connstr]
                :end-before: [END create_eventhub_client_connstr]
                :language: python
                :dedent: 4
                :caption: Create an EventHubClient from a connection string.

        """
        address, policy, key, entity = _parse_conn_str(conn_str)
        entity = event_hub_path or entity
        left_slash_pos = address.find("//")
        if left_slash_pos != -1:
            host = address[left_slash_pos + 2:]
        else:
            host = address
        return cls(host, entity, EventHubSharedKeyCredential(policy, key), **kwargs)

    @classmethod
    def from_iothub_connection_string(cls, conn_str, **kwargs):
        """
        Create an EventHubClient from an IoTHub connection string.

        :param conn_str: The connection string.
        :type conn_str: str
        :param network_tracing: Whether to output network trace logs to the logger. Default
         is `False`.
        :type network_tracing: bool
        :param http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: 'proxy_hostname' (str value) and 'proxy_port' (int value).
         Additionally the following keys may also be present: 'username', 'password'.
        :type http_proxy: dict[str, Any]
        :param auth_timeout: The time in seconds to wait for a token to be authorized by the service.
         The default value is 60 seconds. If set to 0, no timeout will be enforced from the client.
        :type auth_timeout: float
        :param user_agent: The user agent that needs to be appended to the built in user agent string.
        :type user_agent: str
        :param max_retries: The max number of attempts to redo the failed operation when an error happened. Default
         value is 3.
        :type max_retries: int
        :param transport_type: The transport protocol type - default is ~uamqp.TransportType.Amqp.
         ~uamqp.TransportType.AmqpOverWebsocket is applied when http_proxy is set or the
         transport type is explicitly requested.
        :type transport_type: ~azure.eventhub.TransportType
        :param prefetch: The message prefetch count of the receiver. Default is 300.
        :type prefetch: int
        :param max_batch_size: Receive a batch of events. Batch size will be up to the maximum specified, but
         will return as soon as service returns no new events. Default value is the same as prefetch.
        :type max_batch_size: int
        :param receive_timeout: The timeout time in seconds to receive a batch of events from an Event Hub.
         Default value is 0 seconds.
        :type receive_timeout: float
        :param send_timeout: The timeout in seconds for an individual event to be sent from the time that it is
         queued. Default value is 60 seconds. If set to 0, there will be no timeout.
        :type send_timeout: float

        Example:
            .. literalinclude:: ../examples/test_examples_eventhub.py
                :start-after: [START create_eventhub_client_iot_connstr]
                :end-before: [END create_eventhub_client_iot_connstr]
                :language: python
                :dedent: 4
                :caption: Create an EventHubClient from an IoTHub connection string.

        """
        address, policy, key, _ = _parse_conn_str(conn_str)
        hub_name = address.split('.')[0]
        username = "{}@sas.root.{}".format(policy, hub_name)
        password = _generate_sas_token(address, policy, key)
        left_slash_pos = address.find("//")
        if left_slash_pos != -1:
            host = address[left_slash_pos + 2:]
        else:
            host = address
        client = cls(host, "", EventHubSharedKeyCredential(username, password), **kwargs)
        client._auth_config = {  # pylint: disable=protected-access
            'iot_username': policy,
            'iot_password': key,
            'username': username,
            'password': password}
        return client

    @abstractmethod
    def _create_auth(self, username=None, password=None):
        pass

    def _create_properties(self, user_agent=None):  # pylint: disable=no-self-use
        """
        Format the properties with which to instantiate the connection.
        This acts like a user agent over HTTP.

        :rtype: dict
        """
        properties = {}
        properties["product"] = "eventhub.python"
        properties["version"] = __version__
        properties["framework"] = "Python {}.{}.{}".format(*sys.version_info[0:3])
        properties["platform"] = sys.platform

        final_user_agent = 'azsdk-python-eventhub/{} ({}; {})'.format(
            __version__, properties["framework"], sys.platform)
        if user_agent:
            final_user_agent = '{}, {}'.format(final_user_agent, user_agent)

        if len(final_user_agent) > constants.MAX_USER_AGENT_LENGTH:
            raise ValueError("The user-agent string cannot be more than {} in length."
                             "Current user_agent string is: {} with length: {}".format(
                                constants.MAX_USER_AGENT_LENGTH, final_user_agent, len(final_user_agent)))

        properties["user-agent"] = final_user_agent
        return properties

    def _process_redirect_uri(self, redirect):
        redirect_uri = redirect.address.decode('utf-8')
        auth_uri, _, _ = redirect_uri.partition("/ConsumerGroups")
        self.address = urlparse(auth_uri)
        self.host = self.address.hostname
        self.auth_uri = "sb://{}{}".format(self.address.hostname, self.address.path)
        self.eh_name = self.address.path.lstrip('/')
        self.mgmt_target = redirect_uri

    @abstractmethod
    def create_receiver(
            self, partition_id, event_position, consumer_group="$Default", exclusive_receiver_priority=None,
            operation=None,
            prefetch=None,
    ):
        pass

    @abstractmethod
    def create_sender(self, partition_id=None, operation=None, send_timeout=None):
        pass
