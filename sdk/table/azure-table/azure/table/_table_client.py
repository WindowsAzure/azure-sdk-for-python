import functools
from datetime import datetime
from urllib.parse import urlparse, quote

import kwargs
from azure.core.paging import ItemPaged
from azure.table._deserialize import deserialize_table_creation
from azure.table._generated import AzureTable
from azure.table._generated.models import TableProperties, AccessPolicy, SignedIdentifier
from azure.table._message_encoding import NoEncodePolicy, NoDecodePolicy
from azure.table._serialization import _to_entity_datetime, _PYTHON_TO_ENTITY_CONVERSIONS, _EDM_TO_ENTITY_CONVERSIONS, \
    _add_entity_properties, _convert_entity_to_properties
from azure.table._shared.base_client import StorageAccountHostsMixin, parse_query, parse_connection_str
from azure.table._shared.request_handlers import add_metadata_headers, serialize_iso
from azure.table._shared.response_handlers import process_storage_error
from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError
from azure.table._version import VERSION
from azure.core.tracing.decorator import distributed_trace
from ._models import TablePropertiesPaged, TableEntityPropertiesPaged, Entity, EdmType
from ._generated.models import QueryOptions

from ._shared.response_handlers import return_headers_and_deserialized


class TableClient(StorageAccountHostsMixin):
    def __init__(
            self, account_url,  # type: str
            table_name,  # type: str
            credential=None,  # type: Optional[Any]
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        try:
            if not account_url.lower().startswith('http'):
                account_url = "https://" + account_url
        except AttributeError:
            raise ValueError("Account URL must be a string.")
        parsed_url = urlparse(account_url.rstrip('/'))
        if not table_name:
            raise ValueError("Please specify a queue name.")
        if not parsed_url.netloc:
            raise ValueError("Invalid URL: {}".format(parsed_url))

        _, sas_token = parse_query(parsed_url.query)
        if not sas_token and not credential:
            raise ValueError("You need to provide either a SAS token or an account shared key to authenticate.")

        self.table_name = table_name
        self._query_str, credential = self._format_query_string(sas_token, credential)
        super(TableClient, self).__init__(parsed_url, service='table', credential=credential, **kwargs)

        self._config.message_encode_policy = kwargs.get('message_encode_policy', None) or NoEncodePolicy()
        self._config.message_decode_policy = kwargs.get('message_decode_policy', None) or NoDecodePolicy()
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
            table_name,  # type: str
            credential=None,  # type: Any
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Create QueueClient from a Connection String.

        :param str conn_str:
            A connection string to an Azure Storage account.
        :param table_name: The queue name.
        :type table_name: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string, an account shared access
            key, or an instance of a TokenCredentials class from azure.identity.
        :returns: A queue client.
        :rtype: ~azure.storage.queue.QueueClient

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START create_queue_client_from_connection_string]
                :end-before: [END create_queue_client_from_connection_string]
                :language: python
                :dedent: 8
                :caption: Create the queue client from connection string.
        """
        account_url, secondary, credential = parse_connection_str(
            conn_str, credential, 'queue')
        if 'secondary_hostname' not in kwargs:
            kwargs['secondary_hostname'] = secondary
        return cls(account_url, table_name=table_name, credential=credential, **kwargs)  # type: ignore

    @distributed_trace
    def get_table_access_policy(
            self,
            **kwargs
    ):
        timeout = kwargs.pop('timeout', None)
        try:
            _, identifiers = self._client.table.get_access_policy(
                table=self.table_name,
                timeout=timeout,
                cls=return_headers_and_deserialized,
                **kwargs)
        except HttpResponseError as error:
            process_storage_error(error)
        return {s.id: s.access_policy or AccessPolicy() for s in identifiers}

    @distributed_trace
    def set_table_access_policy(self, signed_identifiers, **kwargs):
        # type: (Dict[str, AccessPolicy], Optional[Any]) -> None
        if len(signed_identifiers) > 5:
            raise ValueError(
                'Too many access policies provided. The server does not support setting '
                'more than 5 access policies on a single resource.')
        identifiers = []
        for key, value in signed_identifiers.items():
            if value:
                value.start = serialize_iso(value.start)
                value.expiry = serialize_iso(value.expiry)
            identifiers.append(SignedIdentifier(id=key, access_policy=value))
        try:
            self._client.table.set_access_policy(
                table=self.table_name,
                table_acl=identifiers,
                **kwargs)
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def get_table_properties(self, **kwargs):
        # type: (Optional[Any]) -> TableProperties
        timeout = kwargs.pop('timeout', None)
        request_id_parameter = kwargs.pop('request_id_parameter', None)
        try:
            response = self._client.table.get_properties(
                timeout=timeout,
                request_id_parameter=request_id_parameter,
                **kwargs)
        except HttpResponseError as error:
            process_storage_error(error)
        response.name = self.table_name
        return response  # type: ignore

    @distributed_trace
    def delete_entity(
            self,
            partition_key,
            row_key,
            if_match,
            timeout=None,
            request_id_parameter=None,
            query_options=None
    ):
        try:
            self._client.table.delete_entity(
                table=self.table_name,
                partition_key=partition_key,
                row_key=row_key,
                if_match=if_match)
        except ResourceNotFoundError as error:
            process_storage_error(error)

    @distributed_trace
    def insert_entity(
            self,
            timeout=None,
            request_id_parameter=None,
            response_hook=None,
            table_entity_properties=None,
            query_options=None,
            **kwargs
    ):
        if table_entity_properties:
            table_entity_properties = _add_entity_properties(table_entity_properties)
        try:

            inserted_entity = self._client.table.insert_entity(
                table=self.table_name,
                table_entity_properties=table_entity_properties,
                query_options=query_options,
                **kwargs
            )
        # return inserted_entity
        except ValueError as error:
            process_storage_error(error)

    @distributed_trace
    def update_entity(
            self,
            partition_key=None,
            row_key=None,
            timeout=None,
            request_id_parameter=None,
            if_match=None,
            response_hook=None,
            table_entity_properties=None,
            query_options=None,
            **kwargs
    ):
        if table_entity_properties:
            partition_key = table_entity_properties['PartitionKey'] if partition_key is None else partition_key
            row_key = table_entity_properties['RowKey'] if row_key is None else row_key
            table_entity_properties = _add_entity_properties(table_entity_properties)

        try:
            updated_entity = self._client.table.update_entity(
                table=self.table_name,
                partition_key=partition_key,
                row_key=row_key,
                table_entity_properties=table_entity_properties,
                **kwargs)
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def merge_entity(
            self,
            partition_key,  # type: str
            row_key,  # type: str
            timeout=None,  # type: Optional[int]
            request_id_parameter=None,  # type: Optional[str]
            if_match=None,  # type: Optional[str]
            table_entity_properties=None,  # type: Optional[Dict[str, object]]
            query_options=None,  # type: Optional["models.QueryOptions"]
            **kwargs  # type: Any
    ):
        try:
            merged_entity = self._client.table.merge_entity(table=self.table_name, partition_key=partition_key,
                                                            row_key=row_key)
            return merged_entity
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def query_entities(self, partition_key, row_key, query_options=None):
        command = functools.partial(
            self._client.table.query_entities_with_partition_and_row_key)
        return ItemPaged(
            command, results_per_page=query_options, row_key=row_key, table=self.table_name,
            partition_key=partition_key,
            page_iterator_class=TableEntityPropertiesPaged
        )

    @distributed_trace
    def query_entities_with_partition_and_row_key(self, partition_key, row_key, query_options=None):
        try:
            entity = self._client.table.query_entities_with_partition_and_row_key(table=self.table_name,
                                                                                  partition_key=partition_key,
                                                                                  row_key=row_key,
                                                                                  query_options=query_options)
            entity_properties = entity.additional_properties
            properties = _convert_entity_to_properties(entity_properties)
            return Entity(properties)
        except ResourceExistsError as error:
            process_storage_error(error)

    @distributed_trace
    def upsert_insert_merge_entity(
            self,
            partition_key,
            row_key,
            timeout=None,
            request_id_parameter=None,
            if_match=None,
            table_entity_properties=None,
            query_options=None
    ):
        # Insert or Merge
        try:
            merge_entity = self.merge_entity(
                partition_key=partition_key,
                row_key=row_key
            )
            # update_entity = self.update_entity(partition_key=partition_key,row_key=row_key)
            return merge_entity
        except ResourceNotFoundError:
            insert_entity = self.insert_entity(
                partition_key=partition_key,
                row_key=row_key
            )
            return insert_entity

    def upsert_insert_update_entity(
            self,
            partition_key,
            row_key,
            timeout=None,
            request_id_parameter=None,
            if_match=None,
            table_entity_properties=None,
            query_options=None
    ):
        # Insert or Update
        try:
            update_entity = self.update_entity(partition_key=partition_key, row_key=row_key)
            return update_entity
        except ResourceNotFoundError:
            insert_entity = self.insert_entity(
                partition_key=partition_key,
                row_key=row_key
            )
            return insert_entity
