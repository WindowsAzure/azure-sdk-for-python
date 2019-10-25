# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import six

from azure.storage.blob._shared.base_client import parse_connection_str
from azure.storage.blob._shared.request_handlers import get_length, read_length
from azure.storage.blob._shared.response_handlers import return_response_headers, process_storage_error
from azure.storage.blob._lease import get_access_conditions
from azure.storage.file.datalake._generated.models import StorageErrorException
from azure.storage.file.datalake._path_client import PathClient
from azure.storage.file.datalake._serialize import get_mod_conditions, get_path_http_headers


class FileClient(PathClient):
    def __init__(
        self, account_url,  # type: str
        file_system_name,  # type: str
        file_directory,  # type: str
        file_name,  # type: str
        credential=None,  # type: Optional[Any]
        **kwargs  # type: Any
    ):
        if file_directory:
            path = file_directory.rstrip('/') + "/" + file_name
        else:
            path = file_name
        super(FileClient, self).__init__(account_url, file_system_name, path,
                                         credential=credential, **kwargs)

    def generate_shared_access_signature(self):
        # ???
        pass

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            file_system_name,  # type: str
            directory_name,  # type: str
            file_name,  # type: str
            credential=None,  # type: Optional[Any]
            **kwargs  # type: Any
        ):  # type: (...) -> FileClient
        """
        Create FileClient from a Connection String.

        :param str conn_str:
            A connection string to an Azure Storage account.
        :param file_system_name: The name of file system to interact with.
        :type file_system_name: str
        :param directory_name: The name of directory to interact with. The directory is under file system.
        :type directory_name: str
        :param file_name: The name of file to interact with. The file is under directory.
        :type file_name: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string, and account shared access
            key, or an instance of a TokenCredentials class from azure.identity.
            Credentials provided here will take precedence over those in the connection string.
        :return a FileClient
        :rtype ~azure.storage.file.datalake.FileClient
        """
        account_url, secondary, credential = parse_connection_str(conn_str, credential, 'dfs')
        if 'secondary_hostname' not in kwargs:
            kwargs['secondary_hostname'] = secondary
        return cls(
            account_url, file_system_name=file_system_name, directory_name=directory_name, file_name=file_name,
            credential=credential, **kwargs)

    def create_file(self, content_settings=None, metadata=None, **kwargs):
        """
        Create directory or file
        :return:
        """
        return self.create_path('file', content_settings=content_settings, metadata=metadata, **kwargs)

    def delete_file(self, **kwargs):
        # type: (...) -> None
        """
        Marks the specified path for deletion.
        :return:
        """
        return self.delete_path(**kwargs)

    @staticmethod
    def _append_data_options(data, offset, length=None, **kwargs):
        # type: (Optional[ContentSettings], Optional[Dict[str, str]], **Any) -> Dict[str, Any]

        if isinstance(data, six.text_type):
            data = data.encode(kwargs.pop('encoding', 'UTF-8'))  # type: ignore
        if length is None:
            length = get_length(data)
            if length is None:
                length, data = read_length(data)
        if isinstance(data, bytes):
            data = data[:length]

        access_conditions = get_access_conditions(kwargs.pop('lease', None)) # TODO: move the method to a right place

        options = {
            'body': data,
            'position': offset,
            'content_length': length,
            'lease_access_conditions': access_conditions,
            'timeout': kwargs.pop('timeout', None),
            'cls': return_response_headers}
        options.update(kwargs)
        return options

    def append_data(self, data, offset, length=None, **kwargs):
        # type: (...) -> Dict[str, Union[str, datetime, int]]
        """

        :param data:
        :param offset:
        :param length:
        :param bool validate_content:
            If true, calculates an MD5 hash of the block content. The storage
            service checks the hash of the content that has arrived
            with the hash that was sent. This is primarily valuable for detecting
            bitflips on the wire if using http instead of https as https (the default)
            will already validate. Note that this MD5 hash is not stored with the
            blob.
        :param lease:
            Required if the blob has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :param kwargs:
        :return:
        """
        options = self._append_data_options(
            data,
            offset,
            length=length,
            **kwargs)
        try:
            return self._client.path.append_data(**options)
        except StorageErrorException as error:
            process_storage_error(error)

    @staticmethod
    def _flush_data_options(offset, content_settings=None, retain_uncommitted_data=False, **kwargs):
        # type: (Optional[ContentSettings], Optional[Dict[str, str]], **Any) -> Dict[str, Any]

        access_conditions = get_access_conditions(kwargs.pop('lease', None)) # TODO: move the method to a right place
        mod_conditions = get_mod_conditions(kwargs)

        path_http_headers = None
        if content_settings:
            path_http_headers = get_path_http_headers(content_settings)

        options = {
            'position': offset,
            'content_length': 0,
            'path_http_headers': path_http_headers,
            'retain_uncommitted_data': retain_uncommitted_data,
            'close': kwargs.pop('close', False),
            'lease_access_conditions': access_conditions,
            'modified_access_conditions': mod_conditions,
            'timeout': kwargs.pop('timeout', None),
            'cls': return_response_headers}
        options.update(kwargs)
        return options

    def flush_data(self, offset, retain_uncommitted_data=False, **kwargs):
        """

        :param offset:
        :param length:
        :param bool retain_uncommitted_data: Valid only for flush operations.  If
         "true", uncommitted data is retained after the flush operation
         completes; otherwise, the uncommitted data is deleted after the flush
         operation.  The default is false.  Data at offsets less than the
         specified position are written to the file when flush succeeds, but
         this optional parameter allows data after the flush position to be
         retained for a future flush operation.
        :param bool close: Azure Storage Events allow applications to receive
         notifications when files change. When Azure Storage Events are
         enabled, a file changed event is raised. This event has a property
         indicating whether this is the final change to distinguish the
         difference between an intermediate flush to a file stream and the
         final close of a file stream. The close query parameter is valid only
         when the action is "flush" and change notifications are enabled. If
         the value of close is "true" and the flush operation completes
         successfully, the service raises a file change notification with a
         property indicating that this is the final update (the file stream has
         been closed). If "false" a change notification is raised indicating
         the file has changed. The default is false. This query parameter is
         set to true by the Hadoop ABFS driver to indicate that the file stream
         has been closed."
        :param ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :param ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :param str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :param str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :param kwargs:
        :return:
        """
        options = self._flush_data_options(
            offset,
            retain_uncommitted_data=retain_uncommitted_data, **kwargs)
        try:
            return self._client.path.flush_data(**options)
        except StorageErrorException as error:
            process_storage_error(error)

    def read_file(self, offset=None, length=None, **kwargs):
        # type: (Optional[int], Optional[int], bool, **Any) -> Iterable[bytes]
        """
        Download a file from the service, including its metadata and properties
        :return:
        """
        self._blob_client.download_blob(offset=offset, length=length, **kwargs)
