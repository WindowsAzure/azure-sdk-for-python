import functools
from typing import (
    Union,
    Optional,
    Any,
    Dict,
    List
)

from azure.core.async_paging import AsyncItemPaged
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline import AsyncPipeline
from azure.core.tracing.decorator import distributed_trace
from azure.core.tracing.decorator_async import distributed_trace_async
from azure.data.tables import VERSION, LocationMode
from azure.data.tables._generated.aio._azure_table_async import AzureTable
from azure.data.tables._generated.models import TableServiceProperties, TableProperties, QueryOptions
from azure.data.tables._models import service_stats_deserialize, service_properties_deserialize
from azure.data.tables._shared.base_client_async import AsyncStorageAccountHostsMixin, AsyncTransportWrapper
from azure.data.tables._shared.policies_async import ExponentialRetry
from azure.data.tables._shared.response_handlers import process_table_error
from azure.data.tables.aio._table_client_async import TableClient
from ._models import TablePropertiesPaged
from .._shared._error import _validate_table_name
from .._shared._table_service_client_base import TableServiceClientBase, _parameter_filter_substitution
from .._models import Table


class TableServiceClient(AsyncStorageAccountHostsMixin, TableServiceClientBase):
    """A client to interact with the Table Service at the account level.

    This client provides operations to retrieve and configure the account properties
    as well as list, create and delete tables within the account.
    For operations relating to a specific queue, a client for this entity
    can be retrieved using the :func:`~get_table_client` function.

    :param str account_url:
        The URL to the table service endpoint. Any other entities included
        in the URL path (e.g. queue) will be discarded. This URL can be optionally
        authenticated with a SAS token.
    :param credential:
        The credentials with which to authenticate. This is optional if the
        account URL already has a SAS token. The value can be a SAS token string, an account
        shared access key, or an instance of a TokenCredentials class from azure.identity.
    :keyword str api_version:
        The Storage API version to use for requests. Default value is '2019-07-07'.
        Setting to an older version may result in reduced feature compatibility.
    :keyword str secondary_hostname:
        The hostname of the secondary endpoint.

    .. admonition:: Example:

        .. literalinclude:: ../samples/table_samples_authentication_async.py
            :start-after: [START async_create_table_service_client]
            :end-before: [END async_create_table_service_client]
            :language: python
            :dedent: 8
            :caption: Creating the tableServiceClient with an account url and credential.

        .. literalinclude:: ../samples/table_samples_authentication_async.py
            :start-after: [START async_create_table_service_client_token]
            :end-before: [END async_create_table_service_client_token]
            :language: python
            :dedent: 8
            :caption: Creating the tableServiceClient with Azure Identity credentials.
    """

    def __init__(
            self, account_url: str,
            credential: Optional[Any]=None,
            **kwargs: Any
    ) -> None:
        kwargs['retry_policy'] = kwargs.get('retry_policy') or ExponentialRetry(**kwargs)
        loop = kwargs.pop('loop', None)
        super(TableServiceClient, self).__init__(  # type: ignore
            account_url,
            service='table',
            credential=credential,
            loop=loop,
            **kwargs)
        self._client = AzureTable(url=self.url, pipeline=self._pipeline, loop=loop)  # type: ignore
        self._client._config.version = kwargs.get('api_version', VERSION)  # pylint: disable=protected-access
        self._loop = loop

    @distributed_trace_async
    async def get_service_stats(self, **kwargs) -> "models.TableServiceStats":
        """Retrieves statistics related to replication for the Table service. It is only available on the secondary
        location endpoint when read-access geo-redundant replication is enabled for the account.

                :keyword callable cls: A custom type or function that will be passed the direct response
                :return: TableServiceStats, or the result of cls(response)
                :rtype: ~azure.data.tables.models.TableServiceStats
                :raises: ~azure.core.exceptions.HttpResponseError
                """
        try:
            timeout = kwargs.pop('timeout', None)
            stats = await self._client.service.get_statistics(  # type: ignore
                timeout=timeout, use_location=LocationMode.SECONDARY, **kwargs)
            return service_stats_deserialize(stats)
        except HttpResponseError as error:
            process_table_error(error)

    @distributed_trace_async
    async def get_service_properties(self, **kwargs) -> "models.TableServiceProperties":
        """Gets the properties of an account's Table service,
        including properties for Analytics and CORS (Cross-Origin Resource Sharing) rules.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: TableServiceProperties, or the result of cls(response)
        :rtype: ~azure.data.tables.models.TableServiceProperties
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        timeout = kwargs.pop('timeout', None)
        try:
            service_props = await self._client.service.get_properties(timeout=timeout, **kwargs)  # type: ignore
            return service_properties_deserialize(service_props)
        except HttpResponseError as error:
            process_table_error(error)

    @distributed_trace_async
    async def set_service_properties(
            self, analytics_logging=None,
            hour_metrics=None,
            minute_metrics=None,
            cors=None,
            **kwargs
    ) -> None:
        """Sets properties for an account's Table service endpoint,
        including properties for Analytics and CORS (Cross-Origin Resource Sharing) rules.

       :param analytics_logging: Properties for analytics
       :type analytics_logging: ~azure.data.tables.TableAnalyticsLogging
       :param hour_metrics: Hour level metrics
       :type hour_metrics: ~azure.data.tables.Metrics
       :param minute_metrics: Minute level metrics
       :type minute_metrics: ~azure.data.tables.Metrics
       :param cors: Cross-origin resource sharing rules
       :type cors: ~azure.data.tables.CorsRule
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
            return await self._client.service.set_properties(props, **kwargs)  # type: ignore
        except HttpResponseError as error:
            process_table_error(error)

    @distributed_trace_async
    async def create_table(
            self,
            table_name: str,
            **kwargs: Any
    ) -> TableClient:
        """Creates a new table under the given account.

        :param headers:
        :param table_name: The Table name.
        :type table_name: ~azure.data.tables._models.Table
        :return: TableClient, or the result of cls(response)
        :rtype: ~azure.data.tables.TableClient or None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        _validate_table_name(table_name)

        table_properties = TableProperties(table_name=table_name, **kwargs)
        await self._client.table.create(table_properties=table_properties, **kwargs)
        table = self.get_table_client(table=table_name)
        return table

    @distributed_trace_async
    async def delete_table(
            self,
            table_name: str,
            **kwargs: Any
    ) -> None:
        """Creates a new table under the given account.

                        :param request_id_parameter: Request Id parameter
                        :type request_id_parameter: str
                        :param table_name: The Table name.
                        :type table_name: str
                        :keyword callable cls: A custom type or function that will be passed the direct response
                        :return: None
                        :rtype: ~None
                        """
        _validate_table_name(table_name)

        await self._client.table.delete(table=table_name, **kwargs)

    @distributed_trace
    def list_tables(
            self,
            **kwargs
    ) -> AsyncItemPaged[Table]:
        """Queries tables under the given account.

        :keyword int results_per_page: Number of tables per page in return ItemPaged
        :keyword Union[str, list(str)] select: Specify desired properties of a table to return certain tables
        :return: AsyncItemPaged
        :rtype: ~AsyncItemPaged[str]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        user_select = kwargs.pop('select', None)
        if user_select and not isinstance(user_select, str):
            user_select = ", ".join(user_select)

        query_options = QueryOptions(top=kwargs.pop('results_per_page', None), select=user_select)

        command = functools.partial(
            self._client.table.query,
            query_options=query_options,
            **kwargs)
        return AsyncItemPaged(
            command,
            page_iterator_class=TablePropertiesPaged
        )

    @distributed_trace
    def query_tables(
            self,
            filter: List[str],
            **kwargs: Any
    ) -> AsyncItemPaged[str]:
        """Queries tables under the given account.

        :param filter: Specify a filter to return certain tables
        :type filter: str
        :keyword int results_per_page: Number of tables per page in return ItemPaged
        :keyword Union[str, list(str)] select: Specify desired properties of a table to return certain tables
        :keyword dict parameters: Dictionary for formatting query with additional, user defined parameters
        :return: AsyncItemPaged
        :rtype: ~AsyncItemPaged[str]
        :raises: ~azure.core.exceptions.HttpResponseError
        """

        parameters = kwargs.pop('parameters', None)
        filter = _parameter_filter_substitution(parameters, filter)  # pylint: disable=W0622

        user_select = kwargs.pop('select', None)
        if user_select and not isinstance(user_select, str):
            user_select = ", ".join(user_select)

        query_options = QueryOptions(top=kwargs.pop('results_per_page', None), select=user_select,
                                     filter=filter)

        command = functools.partial(self._client.table.query, query_options=query_options, 
                                    **kwargs)
        return AsyncItemPaged(
            command,
            page_iterator_class=TablePropertiesPaged
        )

    def get_table_client(
        self, 
        table: Union[TableProperties, str],
        **kwargs: Any
    ) -> TableClient:
        """Get a client to interact with the specified table.

               The table need not already exist.

               :param table:
                   The queue. This can either be the name of the queue,
                   or an instance of QueueProperties.
               :type table: str or ~azure.storage.table.TableProperties
               :returns: A :class:`~azure.data.tables.TableClient` object.
               :rtype: ~azure.data.tables.TableClient

               """
        try:
            table_name = table.name
        except AttributeError:
            table_name = table

        # TODO: transport wrapper for pipeline
        _pipeline = AsyncPipeline(
            transport=AsyncTransportWrapper(self._pipeline._transport),  # pylint: disable = protected-access
            policies=self._pipeline._impl_policies  # pylint: disable = protected-access
        )

        return TableClient(
            self.url, table_name=table_name, credential=self.credential,
            key_resolver_function=self.key_resolver_function, require_encryption=self.require_encryption,
            key_encryption_key=self.key_encryption_key, api_version=self.api_version, _pipeline=self._pipeline,
            _configuration=self._config, _location_mode=self._location_mode, _hosts=self._hosts, **kwargs)
