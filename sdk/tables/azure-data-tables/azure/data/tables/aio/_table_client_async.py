# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import functools
from typing import (
    Union,
    Any,
)

try:
    from urllib.parse import urlparse, unquote
except ImportError:
    from urlparse import urlparse  # type: ignore
    from urllib2 import unquote  # type: ignore

from azure.core.async_paging import AsyncItemPaged
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
from azure.core.tracing.decorator import distributed_trace
from azure.core.tracing.decorator_async import distributed_trace_async

from .. import VERSION
from .._base_client import parse_connection_str
from .._entity import TableEntity
from .._generated.aio import AzureTable
from .._generated.models import SignedIdentifier, TableProperties, QueryOptions
from .._models import AccessPolicy, Table
from .._serialize import serialize_iso
from .._deserialize import _return_headers_and_deserialized
from .._error import _process_table_error
from .._models import UpdateMode
from .._deserialize import _convert_to_entity
from .._serialize import _add_entity_properties, _get_match_headers
from .._table_client_base import TableClientBase
from ._base_client_async import AsyncStorageAccountHostsMixin
from ._models import TableEntityPropertiesPaged
from ._policies_async import ExponentialRetry


class TableClient(AsyncStorageAccountHostsMixin, TableClientBase):
    """ :ivar str account_name: Name of the storage account (Cosmos or Azure)"""

    def __init__(
            self,
            account_url,  # type: str
            table_name,  # type: str
            credential,  # type : Optional[Any]=None
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Create TableClient from a Credential.

              :param account_url:
                  A url to an Azure Storage account.
              :type account_url: str
              :param table_name: The table name.
              :type table_name: str
              :param credential:
                  The credentials with which to authenticate. This is optional if the
                  account URL already has a SAS token, or the connection string already has shared
                  access key values. The value can be a SAS token string, an account shared access
                  key.
              :type credential: str

              :returns: None
              """
        kwargs["retry_policy"] = kwargs.get("retry_policy") or ExponentialRetry(**kwargs)
        loop = kwargs.pop('loop', None)
        super(TableClient, self).__init__(
            account_url, table_name=table_name, credential=credential, loop=loop, **kwargs
        )
        self._client = AzureTable(self.url, pipeline=self._pipeline, loop=loop)
        self._client._config.version = kwargs.get('api_version', VERSION)  # pylint: disable = W0212
        self._loop = loop

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            table_name,  # type: str
            **kwargs  # type: Any
    ):
        # type: (...) -> TableClient
        """Create TableClient from a Connection String.

        :param conn_str:
            A connection string to an Azure Storage or Cosmos account.
        :type conn_str: str
        :param table_name: The table name.
        :type table_name: str
        :returns: A table client.
        :rtype: ~azure.data.tables.TableClient
        """
        account_url, credential = parse_connection_str(
            conn_str=conn_str, credential=None, service='table', keyword_args=kwargs)
        return cls(account_url, table_name=table_name, credential=credential, **kwargs)

    @classmethod
    def from_table_url(cls, table_url, credential=None, **kwargs):
        # type: (str, Optional[Any], Any) -> TableClient
        """A client to interact with a specific Table.

        :param table_url: The full URI to the table, including SAS token if used.
        :type table_url: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token. The value can be a SAS token string, an account
            shared access key.
        :type credential: str
        :returns: A table client.
        :rtype: ~azure.data.tables.TableClient
        """
        try:
            if not table_url.lower().startswith('http'):
                table_url = "https://" + table_url
        except AttributeError:
            raise ValueError("Table URL must be a string.")
        parsed_url = urlparse(table_url.rstrip('/'))

        if not parsed_url.netloc:
            raise ValueError("Invalid URL: {}".format(table_url))

        table_path = parsed_url.path.lstrip('/').split('/')
        account_path = ""
        if len(table_path) > 1:
            account_path = "/" + "/".join(table_path[:-1])
        account_url = "{}://{}{}?{}".format(
            parsed_url.scheme,
            parsed_url.netloc.rstrip('/'),
            account_path,
            parsed_url.query)
        table_name = unquote(table_path[-1])
        if not table_name:
            raise ValueError("Invalid URL. Please provide a URL with a valid table name")
        return cls(account_url, table_name=table_name, credential=credential, **kwargs)

    @distributed_trace_async
    async def get_table_access_policy(
            self,
            **kwargs  # type: Any
    ):
        # type: (...) -> dict[str,AccessPolicy]
        """
        Retrieves details about any stored access policies specified on the table that may be
        used with Shared Access Signatures.
        :return: Dictionary of SignedIdentifiers
        :rtype: dict[str,~azure.data.tables.AccessPolicy]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        timeout = kwargs.pop('timeout', None)
        try:
            _, identifiers = await self._client.table.get_access_policy(
                table=self.table_name,
                timeout=timeout,
                cls=kwargs.pop('cls', None) or _return_headers_and_deserialized,
                **kwargs)
        except HttpResponseError as error:
            _process_table_error(error)
        return {s.id: s.access_policy or AccessPolicy() for s in identifiers}

    @distributed_trace_async
    async def set_table_access_policy(
            self,
            signed_identifiers,  # type: dict[str,AccessPolicy]
            **kwargs):
        # type: (...) -> None
        """Sets stored access policies for the table that may be used with Shared Access Signatures.

        :param signed_identifiers:
        :type signed_identifiers: dict[str,AccessPolicy]
        :return: None
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        self._validate_signed_identifiers(signed_identifiers)
        identifiers = []
        for key, value in signed_identifiers.items():
            if value:
                value.start = serialize_iso(value.start)
                value.expiry = serialize_iso(value.expiry)
            identifiers.append(SignedIdentifier(id=key, access_policy=value))
        signed_identifiers = identifiers  # type: ignore
        try:
            await self._client.table.set_access_policy(
                table=self.table_name,
                table_acl=signed_identifiers or None,
                **kwargs)
        except HttpResponseError as error:
            _process_table_error(error)

    @distributed_trace_async
    async def create_table(
            self,
            **kwargs  # type: Any
    ):
        # type: (...) -> Table
        """Creates a new table under the given account.
        :return: Table created
        :rtype: Table
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        table_properties = TableProperties(table_name=self.table_name, **kwargs)
        try:
            table = await self._client.table.create(table_properties)
            return Table(table)
        except HttpResponseError as error:
            _process_table_error(error)

    @distributed_trace_async
    async def delete_table(
            self,
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Creates a new table under the given account.
        :return: None
        :rtype: None
        """
        try:
            await self._client.table.delete(table=self.table_name, **kwargs)
        except HttpResponseError as error:
            _process_table_error(error)

    @distributed_trace_async
    async def delete_entity(
            self,
            partition_key,  # type: str
            row_key,  # type: str
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Deletes the specified entity in a table.
        :param partition_key: The partition key of the entity.
        :type partition_key: str
        :param row_key: The row key of the entity.
        :type row_key: str
        :keyword str etag: Etag of the entity
        :keyword  ~azure.core.MatchConditions match_condition: MatchCondition
        :return: None
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        if_match, if_not_match = _get_match_headers(kwargs=dict(kwargs, etag=kwargs.pop('etag', None),
                                                                match_condition=kwargs.pop('match_condition', None)),
                                                    etag_param='etag', match_param='match_condition')
        try:
            await self._client.table.delete_entity(
                table=self.table_name,
                partition_key=partition_key,
                row_key=row_key,
                if_match=if_match or if_not_match or '*',
                **kwargs)
        except HttpResponseError as error:
            _process_table_error(error)

    @distributed_trace_async
    async def create_entity(
            self,
            entity,  # type: Union[TableEntity, dict[str,str]]
            **kwargs  # type: Any
    ):
        # type: (...) -> TableEntity
        """Insert entity in a table.
        :param entity: The properties for the table entity.
        :type entity: dict[str, str]
        :return: TableEntity mapping str to azure.data.tables.EntityProperty
        :rtype: ~azure.data.tables.TableEntity
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        if "PartitionKey" in entity and "RowKey" in entity:
            entity = _add_entity_properties(entity)
        else:
            raise ValueError('PartitionKey and RowKey were not provided in entity')
        try:
            metadata, identifiers = await self._client.table.insert_entity(
                table=self.table_name,
                table_entity_properties=entity,
                cls=kwargs.pop('cls', _return_headers_and_deserialized),
                **kwargs
            )
            return metadata
        except ResourceNotFoundError as error:
            _process_table_error(error)

    @distributed_trace_async
    async def update_entity(
            self,
            entity,  # type: Union[TableEntity, dict[str,str]]
            mode=UpdateMode.MERGE,  # type: UpdateMode
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Update entity in a table.
        :param mode: Merge or Replace entity
        :type mode: ~azure.data.tables.UpdateMode
        :param entity: The properties for the table entity.
        :type entity: dict[str, str]
        :param partition_key: The partition key of the entity.
        :type partition_key: str
        :param row_key: The row key of the entity.
        :type row_key: str
        :param etag: Etag of the entity
        :type etag: str
        :param match_condition: MatchCondition
        :type match_condition: ~azure.core.MatchConditions
        :return: None
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        if_match, if_not_match = _get_match_headers(kwargs=dict(kwargs, etag=kwargs.pop('etag', None),
                                                                match_condition=kwargs.pop('match_condition', None)),
                                                    etag_param='etag', match_param='match_condition')

        partition_key = entity['PartitionKey']
        row_key = entity['RowKey']
        entity = _add_entity_properties(entity)
        try:
            if mode is UpdateMode.REPLACE:
                metadata, identifiers = await self._client.table.update_entity(
                    table=self.table_name,
                    partition_key=partition_key,
                    row_key=row_key,
                    table_entity_properties=entity,
                    if_match=if_match or if_not_match or "*",
                    cls=kwargs.pop('cls', _return_headers_and_deserialized),
                    **kwargs)
                return metadata
            elif mode is UpdateMode.MERGE:
                metadata, identifiers = await self._client.table.merge_entity(
                    table=self.table_name,
                    partition_key=partition_key,
                    row_key=row_key,
                    if_match=if_match or if_not_match or "*",
                    cls=kwargs.pop('cls', _return_headers_and_deserialized),
                    table_entity_properties=entity, **kwargs)
                return metadata
            else:
                raise ValueError('Mode type is not supported')
        except HttpResponseError as error:
            _process_table_error(error)

    @distributed_trace
    def list_entities(
            self,
            **kwargs  # type: Any
    ):
        # type: (...) -> AsyncItemPaged[TableEntity]
        """Lists entities in a table.

        :keyword int results_per_page: Number of entities per page in return ItemPaged
        :keyword Union[str, list(str)] select: Specify desired properties of an entity to return certain entities
        :return: Query of table entities
        :rtype: AsyncItemPaged[TableEntity]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        user_select = kwargs.pop('select', None)
        if user_select and not isinstance(user_select, str):
            user_select = ", ".join(user_select)

        query_options = QueryOptions(top=kwargs.pop('results_per_page', None), select=user_select)

        command = functools.partial(
            self._client.table.query_entities,
            **kwargs)
        return AsyncItemPaged(
            command, results_per_page=query_options, table=self.table_name,
            page_iterator_class=TableEntityPropertiesPaged
        )

    @distributed_trace
    def query_entities(
            self,
            filter,  # type: str  # pylint: disable = W0622
            **kwargs
    ):
        # type: (...) -> AsyncItemPaged[TableEntity]
        """Lists entities in a table.

        :param str filter: Specify a filter to return certain entities
        :keyword int results_per_page: Number of entities per page in return ItemPaged
        :keyword Union[str, list[str]] select: Specify desired properties of an entity to return certain entities
        :keyword dict parameters: Dictionary for formatting query with additional, user defined parameters
        :return: Query of table entities
        :rtype: ItemPaged[TableEntity]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        parameters = kwargs.pop('parameters', None)
        filter = self._parameter_filter_substitution(parameters, filter)  # pylint: disable = W0622

        user_select = kwargs.pop('select', None)
        if user_select and not isinstance(user_select, str):
            user_select = ", ".join(user_select)

        query_options = QueryOptions(top=kwargs.pop('results_per_page', None), select=user_select,
                                     filter=filter)

        command = functools.partial(
            self._client.table.query_entities,
            query_options=query_options,
            **kwargs)
        return AsyncItemPaged(
            command, table=self.table_name,
            page_iterator_class=TableEntityPropertiesPaged
        )

    @distributed_trace_async
    async def get_entity(
            self,
            partition_key,  # type: str
            row_key,  # type: str
            **kwargs  # type: Any
    ):
        # type: (...) -> TableEntity
        """Queries entities in a table.
        :param partition_key: The partition key of the entity.
        :type partition_key: str
        :param row_key: The row key of the entity.
        :type row_key: str
        :return: TableEntity mapping str to azure.data.tables.EntityProperty
        :rtype: ~azure.data.tables.TableEntity
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        try:
            entity = await self._client.table.query_entities_with_partition_and_row_key(table=self.table_name,
                                                                                        partition_key=partition_key,
                                                                                        row_key=row_key,
                                                                                        **kwargs)

            properties = _convert_to_entity(entity)
            return properties
        except HttpResponseError as error:
            _process_table_error(error)

    @distributed_trace_async
    async def upsert_entity(
            self,
            entity,  # type: Union[TableEntity, dict[str,str]]
            mode=UpdateMode.MERGE,  # type: UpdateMode
            **kwargs  # type: Any
    ):
        # type: (...) -> None

        """Update/Merge or Insert entity into table.
        :param mode: Merge or Replace and Insert on fail
        :type mode: ~azure.data.tables.UpdateMode
        :param entity: The properties for the table entity.
        :type entity: dict[str, str]
        :return: Entity mapping str to azure.data.tables.EntityProperty or None
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """

        partition_key = entity['PartitionKey']
        row_key = entity['RowKey']
        entity = _add_entity_properties(entity)

        try:
            if mode is UpdateMode.MERGE:
                metadata, identifiers = await self._client.table.merge_entity(
                    table=self.table_name,
                    partition_key=partition_key,
                    row_key=row_key,
                    table_entity_properties=entity,
                    cls=kwargs.pop('cls', _return_headers_and_deserialized),
                    **kwargs
                )
                return metadata
            elif mode is UpdateMode.REPLACE:
                metadata, identifiers = await self._client.table.update_entity(
                    table=self.table_name,
                    partition_key=partition_key,
                    row_key=row_key,
                    table_entity_properties=entity,
                    cls=kwargs.pop('cls', _return_headers_and_deserialized),
                    **kwargs)
                return metadata
            else:
                raise ValueError('Mode type is not supported')
        except ResourceNotFoundError:
            return await self.create_entity(
                partition_key=partition_key,
                row_key=row_key,
                table_entity_properties=entity,
                **kwargs
            )
