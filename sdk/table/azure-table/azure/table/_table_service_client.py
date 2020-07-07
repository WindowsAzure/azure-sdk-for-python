# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import functools
from typing import Any

from azure.core.pipeline import Pipeline

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse  # type: ignore

from azure.table._generated import AzureTable
from azure.table._generated.models import TableProperties, TableServiceProperties
from azure.table._models import TablePropertiesPaged, service_stats_deserialize, service_properties_deserialize
from azure.table._shared.base_client import StorageAccountHostsMixin, parse_connection_str, parse_query, \
    TransportWrapper
from azure.table._shared.models import LocationMode
from azure.table._shared.response_handlers import process_storage_error
from azure.table._version import VERSION
from azure.core.exceptions import HttpResponseError
from azure.core.paging import ItemPaged
from azure.core.tracing.decorator import distributed_trace
from azure.table._table_client import TableClient


class TableServiceClient(StorageAccountHostsMixin):
    def __init__(
            self, account_url,  # type: str
            credential=None,  # type: Union[str,TokenCredential]
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Create TableServiceClient from a Credential.

        :param account_url:
            A url to an Azure Storage account.
        :type account_url: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string, an account shared access
            key, or an instance of a TokenCredentials class from azure.identity.
        :type credential: Union[str,TokenCredential]
        :returns: None
        """

        try:
            if not account_url.lower().startswith('http'):
                account_url = "https://" + account_url
        except AttributeError:
            raise ValueError("Account URL must be a string.")
        parsed_url = urlparse(account_url.rstrip('/'))
        if not parsed_url.netloc:
            raise ValueError("Invalid URL: {}".format(account_url))

        _, sas_token = parse_query(parsed_url.query)
        if not sas_token and not credential:
            raise ValueError("You need to provide either a SAS token or an account shared key to authenticate.")
        self._query_str, credential = self._format_query_string(sas_token, credential)
        super(TableServiceClient, self).__init__(parsed_url, service='table', credential=credential, **kwargs)
        self._client = AzureTable(self.url, pipeline=self._pipeline)
        self._client._config.version = kwargs.get('api_version', VERSION)  # pylint: disable=protected-access

    def _format_url(self, hostname):
        """Format the endpoint URL according to the current location
        mode hostname.
        """
        return "{}://{}/{}".format(self.scheme, hostname, self._query_str)

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            credential=None,  # type: Union[str,TokenCredential]
            **kwargs  # type: Any
    ):  # type: (...) -> TableServiceClient
        """Create TableServiceClient from a Connection String.

        :param conn_str:
            A connection string to an Azure Storage account.
        :type conn_str: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string, an account shared access
            key, or an instance of a TokenCredentials class from azure.identity.
        :type credential: Union[str,TokenCredential]
        :returns: A Table service client.
        :rtype: ~azure.storage.table.TableServiceClient
        """
        account_url, secondary, credential = parse_connection_str(
            conn_str, credential, 'table')
        if 'secondary_hostname' not in kwargs:
            kwargs['secondary_hostname'] = secondary
        return cls(account_url, credential=credential, **kwargs)

    @distributed_trace
    def get_service_stats(self, **kwargs):
        # type: (...) -> dict
        """Retrieves statistics related to replication for the Table service. It is only available on the secondary
        location endpoint when read-access geo-redundant replication is enabled for the account.

        :return: Dictionary of Service Stats
        :rtype: dict
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        try:
            timeout = kwargs.pop('timeout', None)
            stats = self._client.service.get_statistics(  # type: ignore
                timeout=timeout, use_location=LocationMode.SECONDARY, **kwargs)
            return service_stats_deserialize(stats)
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def get_service_properties(self, **kwargs):
        # type: (...) -> dict
        """Gets the properties of an account's Table service,
        including properties for Analytics and CORS (Cross-Origin Resource Sharing) rules.

        :return: Dictionary of service properties
        :rtype: dict
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        timeout = kwargs.pop('timeout', None)
        try:
            service_props = self._client.service.get_properties(timeout=timeout, **kwargs)  # type: ignore
            return service_properties_deserialize(service_props)
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def set_service_properties(
            self,
            analytics_logging=None,  # type: Optional[Any]
            hour_metrics=None,  # type: Optional[Any]
            minute_metrics=None,  # type: Optional[Any]
            cors=None,  # type: Optional[Any]
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Sets properties for an account's Table service endpoint,
        including properties for Analytics and CORS (Cross-Origin Resource Sharing) rules.

       :param analytics_logging: Properties for analytics
       :type analytics_logging: Any
       :param hour_metrics: Hour level metrics
       :type hour_metrics: Any
       :param minute_metrics: Minute level metrics
       :type minute_metrics: Any
       :param cors: Cross-origin resource sharing rules
       :type cors: Any
       :return: None
       :rtype: None
       :raises: ~azure.core.exceptions.HttpResponseError
       """
        props = TableServiceProperties(
            logging=analytics_logging,
            hour_metrics=hour_metrics,
            minute_metrics=minute_metrics,
            cors=cors
        )
        try:
            return self._client.service.set_properties(props, **kwargs)  # type: ignore
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def create_table(
            self,
            table_name,  # type: str
            **kwargs  # type: Any
    ):
        # type: (...) -> TableClient
        """Creates a new table under the given account.

        :param table_name: The Table name.
        :type table_name: str
        :return: TableClient, or the result of cls(response)
        :rtype: ~azure.table.TableClient
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        table_properties = TableProperties(table_name=table_name, **kwargs)
        self._client.table.create(table_properties)
        table = self.get_table_client(table=table_name)
        return table

    @distributed_trace
    def delete_table(
            self,
            table_name,  # type: str
            request_id_parameter=None,  # type: Optional[str]
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Creates a new table under the given account.

        :param table_name: The Table name.
        :type table_name: str
        :param request_id_parameter: Request Id parameter
        :type request_id_parameter: str
        :return: None
        :rtype: None
        """
        self._client.table.delete(table=table_name, request_id_parameter=request_id_parameter, **kwargs)

    @distributed_trace
    def query_tables(
            self,
            query_options=None,  # type: Optional[QueryOptions]
            **kwargs  # type: Any
    ):
        # type: (...) -> ItemPaged
        """Queries tables under the given account.

        :param query_options: Parameter group.
        :type query_options: ~azure.table.models.QueryOptions
        :return: ItemPaged
        :rtype: ItemPaged
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        command = functools.partial(self._client.table.query,
                                    **kwargs)
        return ItemPaged(
            command, results_per_page=query_options,
            page_iterator_class=TablePropertiesPaged
        )

    def get_table_client(self, table, **kwargs):
        # type: (Union[TableProperties, str], Optional[Any]) -> TableClient
        """Get a client to interact with the specified table.

       The table need not already exist.

       :param table:
           The table name
       :type table: str
       :returns: A :class:`~azure.table.TableClient` object.
       :rtype: ~azure.table.TableClient

       """
        try:
            table_name = table.name
        except AttributeError:
            table_name = table

        _pipeline = Pipeline(
            transport=TransportWrapper(self._pipeline._transport),  # pylint: disable = protected-access
            policies=self._pipeline._impl_policies  # pylint: disable = protected-access
        )

        return TableClient(
            self.url, table_name=table_name, credential=self.credential,
            key_resolver_function=self.key_resolver_function, require_encryption=self.require_encryption,
            key_encryption_key=self.key_encryption_key, api_version=self.api_version, _pipeline=_pipeline,
            _configuration=self._config, _location_mode=self._location_mode, _hosts=self._hosts, **kwargs)
