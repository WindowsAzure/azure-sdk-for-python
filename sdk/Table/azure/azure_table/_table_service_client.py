from urllib.parse import urlparse

from azure.table import AzureTable
from azure.table import TableProperties
from azure.table import StorageAccountHostsMixin, parse_connection_str, parse_query
from azure.table import VERSION


class TableServiceClient(StorageAccountHostsMixin):
    def __init__(
            self, account_url,  # type: str
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
            credential=None,  # type: Optional[Any]
            **kwargs  # type: Any
    ):  # type: (...) -> TableServiceClient
        """Create TableServiceClient from a Connection String.

        :param str conn_str:
            A connection string to an Azure Storage account.
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string, an account shared access
            key, or an instance of a TokenCredentials class from azure.identity.
        :returns: A Table service client.
        :rtype: ~azure.storage.table.TableClient

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_authentication.py
                :start-after: [START auth_from_connection_string]
                :end-before: [END auth_from_connection_string]
                :language: python
                :dedent: 8
                :caption: Creating the QueueServiceClient with a connection string.
        """
        account_url, secondary, credential = parse_connection_str(
            conn_str, credential, 'queue')
        if 'secondary_hostname' not in kwargs:
            kwargs['secondary_hostname'] = secondary
        return cls(account_url, credential=credential, **kwargs)

    def create_table(self, table_name):
        table_properties = TableProperties(table_name=table_name)
        response = self._client.table.create(table_properties)
        return response

    def delete_table(self, table_name):
        response = self._client.table.delete(table=table_name)
        return response

    def query_table(self, table_name):
        # somehow use self._query_string to query things
        response = self._client.table.query(table_name=table_name)
        return response

    def query_table_entities(self, table_name):
        response = self._client.table.query_entities(table_name=table_name)

    def query_table_entities_with_partition_and_row_key(self, table_name):
        response = self._client.table.query_entities_with_partition_and_row_key(table_name=table_name)

    def insert_entity(self):
        response = self._client.table.insert_entity()

    def delete_entity(self):
        response = self._client.table.delete_entity()

    def merge_entity(self):
        response = self._client.table.merge_entity()

    def update_entity(self):
        response = self._client.table.update_entity()

    def get_access_policy(self):
        response = self._client.table.get_access_policy()

    def set_access_policy(self):
        response = self._client.table.set_access_policy()

    def batch(self, *reqs):
        response = self.batch(*reqs)
        return response
