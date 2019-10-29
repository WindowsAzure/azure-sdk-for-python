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


class DataLakeFileClient(PathClient):
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
        super(DataLakeFileClient, self).__init__(account_url, file_system_name, path,
                                                 credential=credential, **kwargs)

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            file_system_name,  # type: str
            directory_name,  # type: str
            file_name,  # type: str
            credential=None,  # type: Optional[Any]
            **kwargs  # type: Any
        ):  # type: (...) -> DataLakeFileClient
        """
        Create DataLakeFileClient from a Connection String.

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
        :return a DataLakeFileClient
        :rtype ~azure.storage.file.datalake.DataLakeFileClient
        """
        account_url, secondary, credential = parse_connection_str(conn_str, credential, 'dfs')
        if 'secondary_hostname' not in kwargs:
            kwargs['secondary_hostname'] = secondary
        return cls(
            account_url, file_system_name=file_system_name, directory_name=directory_name, file_name=file_name,
            credential=credential, **kwargs)

    def create_file(self, content_settings=None,  # type: Optional[ContentSettings]
                    metadata=None,  # type: Optional[Dict[str, str]]
                    **kwargs):
        # type: (...) -> Dict[str, Union[str, datetime]]
        """
        Create file

        :param ~azure.storage.file.datalake.ContentSettings content_settings:
            ContentSettings object used to set path properties.
        :param metadata:
            Name-value pairs associated with the blob as metadata.
        :type metadata: dict(str, str)
        :keyword ~azure.storage.file.datalake.DataLakeLeaseClient or str lease:
            Required if the blob has an active lease. Value can be a DataLakeLeaseClient object
            or the lease ID as a string.
        :keyword str umask: Optional and only valid if Hierarchical Namespace is enabled for the account.
            When creating a file or directory and the parent folder does not have a default ACL,
            the umask restricts the permissions of the file or directory to be created.
            The resulting permission is given by p & ^u, where p is the permission and u is the umask.
            For example, if p is 0777 and u is 0057, then the resulting permission is 0720.
            The default permission is 0777 for a directory and 0666 for a file. The default umask is 0027.
            The umask must be specified in 4-digit octal notation (e.g. 0766).
        :keyword str permissions: Optional and only valid if Hierarchical Namespace
         is enabled for the account. Sets POSIX access permissions for the file
         owner, the file owning group, and others. Each class may be granted
         read, write, or execute permission.  The sticky bit is also supported.
         Both symbolic (rwxrw-rw-) and 4-digit octal notation (e.g. 0766) are
         supported.
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :keyword str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: response dict (Etag and last modified).
        """
        return self._create('file', content_settings=content_settings, metadata=metadata, **kwargs)

    def delete_file(self, **kwargs):
        # type: (...) -> None
        """
        Marks the specified file for deletion.

        :keyword lease:
            Required if the blob has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :keyword str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: None
        """
        return self._delete(**kwargs)

    def get_file_properties(self, **kwargs):
        # type: (**Any) -> FileProperties
        """Returns all user-defined metadata, standard HTTP properties, and
        system properties for the file. It does not return the content of the file.

        :keyword lease:
            Required if the directory or file has an active lease. Value can be a DataLakeLeaseClient object
            or the lease ID as a string.
        :type lease: ~azure.storage.file.datalake.DataLakeLeaseClient or str
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword :class:`MatchConditions` match_condition:
            The match condition to use upon the etag.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: FileProperties

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_common.py
                :start-after: [START get_blob_properties]
                :end-before: [END get_blob_properties]
                :language: python
                :dedent: 8
                :caption: Getting the properties for a file/directory.
        """
        return self._get_path_properties(**kwargs)

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

    def append_data(self, data,  # type: Union[AnyStr, Iterable[AnyStr], IO[AnyStr]]
                    offset,  # type: int
                    length=None,  # type: Optional[int]
                    **kwargs):
        # type: (...) -> Dict[str, Union[str, datetime, int]]
        """Append data to the file.

        :param data: Content to be appended to file
        :param offset: start position of the data to be appended to.
        :param length: Size of the data in bytes.
        :keyword bool validate_content:
            If true, calculates an MD5 hash of the block content. The storage
            service checks the hash of the content that has arrived
            with the hash that was sent. This is primarily valuable for detecting
            bitflips on the wire if using http instead of https as https (the default)
            will already validate. Note that this MD5 hash is not stored with the
            blob.
        :keyword lease:
            Required if the blob has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :type lease: ~azure.storage.file.datalake.DataLakeLeaseClient or str
        :return: dict of the response header
        """
        options = self._append_data_options(
            data,
            offset,
            length=length,
            **kwargs)
        try:
            return self._client.path.append_data(**options)
        except StorageErrorException as error:
            raise error

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

    def flush_data(self, offset,  # type: int
                   retain_uncommitted_data=False,   # type: Optional[bool]
                   **kwargs):
        # type: (...) -> Dict[str, Union[str, datetime]]
        """ Commit the previous appended data.

        :param offset: the length of the file after commit the previous appended data.
        :param bool retain_uncommitted_data: Valid only for flush operations.  If
            "true", uncommitted data is retained after the flush operation
            completes; otherwise, the uncommitted data is deleted after the flush
            operation.  The default is false.  Data at offsets less than the
            specified position are written to the file when flush succeeds, but
            this optional parameter allows data after the flush position to be
            retained for a future flush operation.
        :keyword bool close: Azure Storage Events allow applications to receive
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
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :keyword str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :return: response header in dict
        """
        options = self._flush_data_options(
            offset,
            retain_uncommitted_data=retain_uncommitted_data, **kwargs)
        try:
            return self._client.path.flush_data(**options)
        except StorageErrorException as error:
            process_storage_error(error)

    def read_file(self, offset=None,   # type: Optional[int]
                  length=None,   # type: Optional[int]
                  stream=None,  # type: Optional[IO]
                  **kwargs):
        # type: (...) -> Union[int, byte]
        """Download a file from the service.

        :param int offset:
            Start of byte range to use for downloading a section of the file.
            Must be set if length is provided.
        :param int length:
            Number of bytes to read from the stream. This is optional, but
            should be supplied for optimal performance.
        :keyword lease:
            If specified, download_blob only succeeds if the blob's lease is active
            and matches this ID. Required if the blob has an active lease.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword :class:`MatchConditions` match_condition:
            The match condition to use upon the etag.
        :keyword int max_concurrency:
            The number of parallel connections with which to download.
        :keyword int timeout:
            The timeout parameter is expressed in seconds. This method may make
            multiple calls to the Azure service and the timeout will apply to
            each call individually.
        :returns: downloaded data or the size of data written into the provided stream
        :rtype: bytes or int

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_hello_world.py
                :start-after: [START download_a_blob]
                :end-before: [END download_a_blob]
                :language: python
                :dedent: 12
                :caption: Download a blob.
        """
        downloader = self._blob_client.download_blob(offset=offset, length=length, **kwargs)
        if stream:
            return downloader.readinto(stream)
        return downloader.readall()
