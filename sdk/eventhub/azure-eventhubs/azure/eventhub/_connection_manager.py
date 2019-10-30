# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from threading import Lock
from enum import Enum
from uamqp import Connection, TransportType, c_uamqp  # type: ignore


class _ConnectionMode(Enum):
    ShareConnection = 1
    SeparateConnection = 2


class _SharedConnectionManager(object):  #pylint:disable=too-many-instance-attributes
    def __init__(self, **kwargs):
        self._lock = Lock()
        self._conn = None  # type: Connection

        self._container_id = kwargs.get("container_id")
        self._debug = kwargs.get("debug")
        self._error_policy = kwargs.get("error_policy")
        self._properties = kwargs.get("properties")
        self._encoding = kwargs.get("encoding") or "UTF-8"
        self._transport_type = kwargs.get('transport_type') or TransportType.Amqp
        self._http_proxy = kwargs.get('http_proxy')
        self._max_frame_size = kwargs.get("max_frame_size")
        self._channel_max = kwargs.get("channel_max")
        self._idle_timeout = kwargs.get("idle_timeout")
        self._remote_idle_timeout_empty_frame_send_ratio = kwargs.get("remote_idle_timeout_empty_frame_send_ratio")

    def get_connection(self, host, auth):
        # type: (...) -> Connection
        with self._lock:
            if self._conn is None:
                self._conn = Connection(
                    host,
                    auth,
                    container_id=self._container_id,
                    max_frame_size=self._max_frame_size,
                    channel_max=self._channel_max,
                    idle_timeout=self._idle_timeout,
                    properties=self._properties,
                    remote_idle_timeout_empty_frame_send_ratio=self._remote_idle_timeout_empty_frame_send_ratio,
                    error_policy=self._error_policy,
                    debug=self._debug,
                    encoding=self._encoding)
            return self._conn

    def close_connection(self):
        with self._lock:
            if self._conn:
                self._conn.destroy()
            self._conn = None

    def reset_connection_if_broken(self):
        with self._lock:
            if self._conn and self._conn._state in (  # pylint:disable=protected-access
                c_uamqp.ConnectionState.CLOSE_RCVD,  # pylint:disable=c-extension-no-member
                c_uamqp.ConnectionState.CLOSE_SENT,  # pylint:disable=c-extension-no-member
                c_uamqp.ConnectionState.DISCARDING,  # pylint:disable=c-extension-no-member
                c_uamqp.ConnectionState.END,  # pylint:disable=c-extension-no-member
            ):
                self._conn = None


class _SeparateConnectionManager(object):
    def __init__(self, **kwargs):
        pass

    def get_connection(self, host, auth):  # pylint:disable=unused-argument, no-self-use
        return None

    def close_connection(self):
        pass

    def reset_connection_if_broken(self):
        pass


def get_connection_manager(**kwargs):
    connection_mode = kwargs.get("connection_mode", _ConnectionMode.ShareConnection)
    if connection_mode == _ConnectionMode.ShareConnection:
        return _SharedConnectionManager(**kwargs)
    else:
        return _SeparateConnectionManager(**kwargs)
