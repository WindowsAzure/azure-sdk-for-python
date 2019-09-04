﻿# The MIT License (MIT)
# Copyright (c) 2014 Microsoft Corporation

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Create, read, and delete databases in the Azure Cosmos DB SQL API service.
"""

from typing import Any, Callable, Dict, Mapping, Optional, Union, cast, Iterable

import six
from azure.core.tracing.decorator import distributed_trace

from ._cosmos_client_connection import CosmosClientConnection
from .database_client import DatabaseClient
from .documents import ConnectionPolicy, DatabaseAccount

__all__ = ("CosmosClient",)


def _parse_connection_str(conn_str, credential):
    conn_str = conn_str.rstrip(";")
    conn_settings = dict( # pylint: disable=consider-using-dict-comprehension
        [s.split("=", 1) for s in conn_str.split(";")]
    )
    if 'AccountEndpoint' not in conn_settings:
        raise ValueError("Connection string missing setting 'AccountEndpoint'.")
    if not credential and 'AccountKey' not in conn_settings:
        raise ValueError("Connection string missing setting 'AccountKey'.")
    return conn_settings


def _build_auth(credential):
    auth = {}
    if isinstance(credential, six.string_types):
        auth['masterKey'] = credential
    elif isinstance(credential, dict):
        if any(k for k in credential.keys() if k in ['masterKey', 'resourceTokens', 'permissionFeed']):
            return credential  # Backwards compatible
        auth['resourceTokens'] = credential
    elif hasattr(credential, '__iter__'):
        auth['permissionFeed'] = credential
    else:
        raise TypeError(
            "Unrecognized credential type. Please supply the master key as str, "
            "or a dictionary or resource tokens, or a list of permissions.")
    return auth


def _build_connection_policy(kwargs):
    # pylint: disable=protected-access
    policy = kwargs.pop('connection_policy', None) or ConnectionPolicy()

    # Connection config
    policy.RequestTimeout = kwargs.pop('request_timeout', None) or \
        kwargs.pop('connection_timeout', None) or \
        policy.RequestTimeout
    policy.MediaRequestTimeout = kwargs.pop('media_request_timeout', None) or policy.MediaRequestTimeout
    policy.ConnectionMode = kwargs.pop('connection_mode', None) or policy.ConnectionMode
    policy.MediaReadMode = kwargs.pop('media_read_mode', None) or policy.MediaReadMode
    policy.ProxyConfiguration = kwargs.pop('proxy_config', None) or policy.ProxyConfiguration
    policy.EnableEndpointDiscovery = kwargs.pop('enable_endpoint_discovery', None) or policy.EnableEndpointDiscovery
    policy.PreferredLocations = kwargs.pop('preferred_locations', None) or policy.PreferredLocations
    policy.UseMultipleWriteLocations = kwargs.pop('multiple_write_locations', None) or \
        policy.UseMultipleWriteLocations

    # SSL config
    verify = kwargs.pop('connection_verify', None)
    policy.DisableSSLVerification = not bool(verify if verify is not None else True)
    ssl = kwargs.pop('ssl_config', None) or policy.SSLConfiguration
    if ssl:
        ssl.SSLCertFile = kwargs.pop('connection_cert', None) or ssl.SSLCertFile
        ssl.SSLCaCerts = verify or ssl.SSLCaCerts
        policy.SSLConfiguration = ssl

    # Retry config
    retry = kwargs.pop('retry_options', None) or policy.RetryOptions
    retry._max_retry_attempt_count = kwargs.pop('retry_total', None) or retry._max_retry_attempt_count
    retry._fixed_retry_interval_in_milliseconds = kwargs.pop('retry_fixed_interval', None) or \
        retry._fixed_retry_interval_in_milliseconds
    retry._max_wait_time_in_seconds = kwargs.pop('retry_backoff_max', None) or retry._max_wait_time_in_seconds
    policy.RetryOptions = retry

    return policy


class CosmosClient(object):
    """
    Provides a client-side logical representation of an Azure Cosmos DB account.
    Use this client to configure and execute requests to the Azure Cosmos DB service.
    """

    def __init__(self, url, credential, consistency_level="Session", **kwargs):
        # type: (str, Dict[str, str], str, ConnectionPolicy) -> None
        """ Instantiate a new CosmosClient.

        :param url: The URL of the Cosmos DB account.
        :param credential:
            Contains 'masterKey' or 'resourceTokens', where
            auth['masterKey'] is the default authorization key to use to
            create the client, and auth['resourceTokens'] is the alternative
            authorization key.
        :param consistency_level: Consistency level to use for the session.
        :param connection_policy: Connection policy to use for the session.

        .. literalinclude:: ../../examples/examples.py
            :start-after: [START create_client]
            :end-before: [END create_client]
            :language: python
            :dedent: 0
            :caption: Create a new instance of the Cosmos DB client:
            :name: create_client

        """
        auth = _build_auth(credential)
        connection_policy = _build_connection_policy(kwargs)
        self.client_connection = CosmosClientConnection(
            url, auth=auth, consistency_level=consistency_level, connection_policy=connection_policy, **kwargs
        )

    def __enter__(self):
        self.client_connection.pipeline_client.__enter__()
        return self

    def __exit__(self, *args):
        return self.client_connection.pipeline_client.__exit__(*args)

    @classmethod
    def from_connection_string(cls, conn_str, credential=None, consistency_level="Session", **kwargs):
        # type: (str, Optional[Any], str, Any) -> CosmosClient
        settings = _parse_connection_str(conn_str, credential)
        return cls(
            url=settings['AccountEndpoint'],
            credential=credential or settings['AccountKey'],
            consistency_level=consistency_level,
            **kwargs
        )

    @staticmethod
    def _get_database_link(database_or_id):
        # type: (str) -> str
        if isinstance(database_or_id, six.string_types):
            return "dbs/{}".format(database_or_id)
        try:
            return cast("DatabaseClient", database_or_id).database_link
        except AttributeError:
            pass
        database_id = cast("Dict[str, str]", database_or_id)["id"]
        return "dbs/{}".format(database_id)

    @distributed_trace
    def create_database(  # pylint: disable=redefined-builtin
        self,
        id,  # type: str
        session_token=None,  # type: Optional[str]
        initial_headers=None,  # type: Optional[Dict[str, str]]
        access_condition=None,  # type: Optional[Dict[str, str]]
        populate_query_metrics=None,  # type: Optional[bool]
        offer_throughput=None,  # type: Optional[int]
        request_options=None,  # type: Optional[Dict[str, Any]]
        response_hook=None,  # type: Optional[Callable]
        **kwargs  # type: Any
    ):
        # type: (...) -> DatabaseClient
        """Create a new database with the given ID (name).

        :param id: ID (name) of the database to create.
        :param session_token: Token for use with Session consistency.
        :param initial_headers: Initial headers to be sent as part of the request.
        :param access_condition: Conditions Associated with the request.
        :param populate_query_metrics: Enable returning query metrics in response headers.
        :param offer_throughput: The provisioned throughput for this offer.
        :param request_options: Dictionary of additional properties to be used for the request.
        :param response_hook: a callable invoked with the response metadata
        :returns: A :class:`DatabaseClient` instance representing the new database.
        :raises `CosmosHttpResponseError`: If database with the given ID already exists.

        .. literalinclude:: ../../examples/examples.py
            :start-after: [START create_database]
            :end-before: [END create_database]
            :language: python
            :dedent: 0
            :caption: Create a database in the Cosmos DB account:
            :name: create_database

        """

        if not request_options:
            request_options = {}  # type: Dict[str, Any]
        if session_token:
            request_options["sessionToken"] = session_token
        if initial_headers:
            request_options["initialHeaders"] = initial_headers
        if access_condition:
            request_options["accessCondition"] = access_condition
        if populate_query_metrics is not None:
            request_options["populateQueryMetrics"] = populate_query_metrics
        if offer_throughput is not None:
            request_options["offerThroughput"] = offer_throughput

        result = self.client_connection.CreateDatabase(database=dict(id=id), options=request_options, **kwargs)
        if response_hook:
            response_hook(self.client_connection.last_response_headers)
        return DatabaseClient(self.client_connection, id=result["id"], properties=result)

    def get_database_client(self, database):
        # type: (Union[str, DatabaseClient, Dict[str, Any]]) -> DatabaseClient
        """
        Retrieve an existing database with the ID (name) `id`.

        :param database: The ID (name), dict representing the properties or :class:`DatabaseClient`
            instance of the database to read.
        :returns: A :class:`DatabaseClient` instance representing the retrieved database.

        """
        if isinstance(database, DatabaseClient):
            id_value = database.id
        elif isinstance(database, Mapping):
            id_value = database["id"]
        else:
            id_value = database

        return DatabaseClient(self.client_connection, id_value)

    @distributed_trace
    def read_all_databases(
        self,
        max_item_count=None,
        session_token=None,
        initial_headers=None,
        populate_query_metrics=None,
        feed_options=None,
        response_hook=None,
        **kwargs
    ):
        # type: (int, str, Dict[str, str], bool, Dict[str, Any],  Optional[Callable]) -> Iterable[Dict[str, Any]]
        """
        List the databases in a Cosmos DB SQL database account.

        :param max_item_count: Max number of items to be returned in the enumeration operation.
        :param session_token: Token for use with Session consistency.
        :param initial_headers: Initial headers to be sent as part of the request.
        :param populate_query_metrics: Enable returning query metrics in response headers.
        :param feed_options: Dictionary of additional properties to be used for the request.
        :param response_hook: a callable invoked with the response metadata
        :returns: An Iterable of database properties (dicts).

        """
        if not feed_options:
            feed_options = {}  # type: Dict[str, Any]
        if max_item_count is not None:
            feed_options["maxItemCount"] = max_item_count
        if session_token:
            feed_options["sessionToken"] = session_token
        if initial_headers:
            feed_options["initialHeaders"] = initial_headers
        if populate_query_metrics is not None:
            feed_options["populateQueryMetrics"] = populate_query_metrics

        result = self.client_connection.ReadDatabases(options=feed_options, **kwargs)
        if response_hook:
            response_hook(self.client_connection.last_response_headers)
        return result

    @distributed_trace
    def query_databases(
        self,
        query=None,  # type: str
        parameters=None,  # type: List[str]
        enable_cross_partition_query=None,  # type: bool
        max_item_count=None,  # type:  int
        session_token=None,  # type: str
        initial_headers=None,  # type: Dict[str,str]
        populate_query_metrics=None,  # type: bool
        feed_options=None,  # type: Dict[str, Any]
        response_hook=None,  # type: Optional[Callable]
        **kwargs
    ):
        # type: (...) -> Iterable[Dict[str, Any]]

        """
        Query the databases in a Cosmos DB SQL database account.

        :param query: The Azure Cosmos DB SQL query to execute.
        :param parameters: Optional array of parameters to the query. Ignored if no query is provided.
        :param enable_cross_partition_query: Allow scan on the queries which couldn't be
            served as indexing was opted out on the requested paths.
        :param max_item_count: Max number of items to be returned in the enumeration operation.
        :param session_token: Token for use with Session consistency.
        :param initial_headers: Initial headers to be sent as part of the request.
        :param populate_query_metrics: Enable returning query metrics in response headers.
        :param feed_options: Dictionary of additional properties to be used for the request.
        :param response_hook: a callable invoked with the response metadata
        :returns: An Iterable of database properties (dicts).

        """
        if not feed_options:
            feed_options = {}  # type: Dict[str, Any]
        if enable_cross_partition_query is not None:
            feed_options["enableCrossPartitionQuery"] = enable_cross_partition_query
        if max_item_count is not None:
            feed_options["maxItemCount"] = max_item_count
        if session_token:
            feed_options["sessionToken"] = session_token
        if initial_headers:
            feed_options["initialHeaders"] = initial_headers
        if populate_query_metrics is not None:
            feed_options["populateQueryMetrics"] = populate_query_metrics

        if query:
            # This is currently eagerly evaluated in order to capture the headers
            # from the call.
            # (just returning a generator did not initiate the first network call, so
            # the headers were misleading)
            # This needs to change for "real" implementation
            query = query if parameters is None else dict(query=query, parameters=parameters)
            result = self.client_connection.QueryDatabases(query=query, options=feed_options, **kwargs)
        else:
            result = self.client_connection.ReadDatabases(options=feed_options, **kwargs)
        if response_hook:
            response_hook(self.client_connection.last_response_headers)
        return result

    @distributed_trace
    def delete_database(
        self,
        database,  # type: Union[str, DatabaseClient, Dict[str, Any]]
        session_token=None,  # type: str
        initial_headers=None,  # type: Dict[str, str]
        access_condition=None,  # type:  Dict[str, str]
        populate_query_metrics=None,  # type: bool
        request_options=None,  # type: Dict[str, Any]
        response_hook=None,  # type: Optional[Callable]
        **kwargs
    ):
        # type: (...) -> None
        """
        Delete the database with the given ID (name).

        :param database: The ID (name), dict representing the properties or :class:`DatabaseClient`
            instance of the database to delete.
        :param session_token: Token for use with Session consistency.
        :param initial_headers: Initial headers to be sent as part of the request.
        :param access_condition: Conditions Associated with the request.
        :param populate_query_metrics: Enable returning query metrics in response headers.
        :param request_options: Dictionary of additional properties to be used for the request.
        :param response_hook: a callable invoked with the response metadata
        :raise CosmosHttpResponseError: If the database couldn't be deleted.

        """
        if not request_options:
            request_options = {}  # type: Dict[str, Any]
        if session_token:
            request_options["sessionToken"] = session_token
        if initial_headers:
            request_options["initialHeaders"] = initial_headers
        if access_condition:
            request_options["accessCondition"] = access_condition
        if populate_query_metrics is not None:
            request_options["populateQueryMetrics"] = populate_query_metrics

        database_link = self._get_database_link(database)
        self.client_connection.DeleteDatabase(database_link, options=request_options, **kwargs)
        if response_hook:
            response_hook(self.client_connection.last_response_headers)

    @distributed_trace
    def get_database_account(self, response_hook=None, **kwargs):
        # type: (Optional[Callable]) -> DatabaseAccount
        """
        Retrieve the database account information.

        :param response_hook: a callable invoked with the response metadata
        :returns: A :class:`DatabaseAccount` instance representing the Cosmos DB Database Account.

        """
        result = self.client_connection.GetDatabaseAccount(**kwargs)
        if response_hook:
            response_hook(self.client_connection.last_response_headers)
        return result
