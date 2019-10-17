# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# pylint: disable=too-many-lines
import functools
import time
from io import BytesIO
from typing import ( # pylint: disable=unused-import
    Optional, Union, IO, List, Dict, Any, Iterable,
    TYPE_CHECKING
)

try:
    from urllib.parse import urlparse, quote, unquote
except ImportError:
    from urlparse import urlparse # type: ignore
    from urllib2 import quote, unquote # type: ignore

import six
from azure.core.paging import ItemPaged
from azure.core.tracing.decorator import distributed_trace

from ._generated import AzureFileStorage
from ._generated.version import VERSION
from ._generated.models import StorageErrorException, FileHTTPHeaders
from ._shared.uploads import IterStreamer, FileChunkUploader, upload_data_chunks
from ._shared.base_client import StorageAccountHostsMixin, parse_connection_str, parse_query
from ._shared.request_handlers import add_metadata_headers, get_length
from ._shared.response_handlers import return_response_headers, process_storage_error
from ._shared.parser import _str
from ._parser import _get_file_permission, _datetime_to_str
from ._deserialize import deserialize_file_properties, deserialize_file_stream
from .models import HandlesPaged, NTFSAttributes  # pylint: disable=unused-import
from ._shared_access_signature import FileSharedAccessSignature
from .download import StorageStreamDownloader

if TYPE_CHECKING:
    from datetime import datetime
    from .models import ShareProperties, FileSasPermissions, ContentSettings, FileProperties
    from ._generated.models import HandleItem


def _upload_file_helper(
        client,
        stream,
        size,
        metadata,
        content_settings,
        validate_content,
        timeout,
        max_concurrency,
        file_settings,
        file_attributes="none",
        file_creation_time="now",
        file_last_write_time="now",
        file_permission=None,
        file_permission_key=None,
        **kwargs):
    try:
        if size is None or size < 0:
            raise ValueError("A content size must be specified for a File.")
        response = client.create_file(
            size,
            content_settings=content_settings,
            metadata=metadata,
            timeout=timeout,
            file_attributes=file_attributes,
            file_creation_time=file_creation_time,
            file_last_write_time=file_last_write_time,
            file_permission=file_permission,
            permission_key=file_permission_key,
            **kwargs
        )
        if size == 0:
            return response

        responses = upload_data_chunks(
            service=client,
            uploader_class=FileChunkUploader,
            total_size=size,
            chunk_size=file_settings.max_range_size,
            stream=stream,
            max_concurrency=max_concurrency,
            validate_content=validate_content,
            timeout=timeout,
            **kwargs
        )
        return sorted(responses, key=lambda r: r.get('last_modified'))[-1]
    except StorageErrorException as error:
        process_storage_error(error)


class FileClient(StorageAccountHostsMixin):
    """A client to interact with a specific file, although that file may not yet exist.

    :ivar str url:
        The full endpoint URL to the File, including SAS token if used. This could be
        either the primary endpoint, or the secondard endpoint depending on the current `location_mode`.
    :ivar str primary_endpoint:
        The full primary endpoint URL.
    :ivar str primary_hostname:
        The hostname of the primary endpoint.
    :ivar str secondary_endpoint:
        The full secondard endpoint URL if configured. If not available
        a ValueError will be raised. To explicitly specify a secondary hostname, use the optional
        `secondary_hostname` keyword argument on instantiation.
    :ivar str secondary_hostname:
        The hostname of the secondary endpoint. If not available this
        will be None. To explicitly specify a secondary hostname, use the optional
        `secondary_hostname` keyword argument on instantiation.
    :ivar str location_mode:
        The location mode that the client is currently using. By default
        this will be "primary". Options include "primary" and "secondary".
    :param str account_url:
        The URI to the storage account. In order to create a client given the full URI to the
        file, use the from_file_url classmethod.
    :param share_name:
        The name of the share for the file.
    :type share_name: str
    :param str file_path:
        The file path to the file with which to interact. If specified, this value will override
        a file value specified in the file URL.
    :param str snapshot:
        An optional file snapshot on which to operate.
    :param credential:
        The credential with which to authenticate. This is optional if the
        account URL already has a SAS token. The value can be a SAS token string or an account
        shared access key.
    """
    def __init__( # type: ignore
            self, account_url,  # type: str
            share_name,  # type: str
            file_path,  # type: str
            snapshot=None,  # type: Optional[Union[str, Dict[str, Any]]]
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
        if not (share_name and file_path):
            raise ValueError("Please specify a share name and file name.")
        if not parsed_url.netloc:
            raise ValueError("Invalid URL: {}".format(account_url))
        if hasattr(credential, 'get_token'):
            raise ValueError("Token credentials not supported by the File service.")

        path_snapshot = None
        path_snapshot, sas_token = parse_query(parsed_url.query)
        if not sas_token and not credential:
            raise ValueError(
                'You need to provide either an account key or SAS token when creating a storage service.')
        try:
            self.snapshot = snapshot.snapshot # type: ignore
        except AttributeError:
            try:
                self.snapshot = snapshot['snapshot'] # type: ignore
            except TypeError:
                self.snapshot = snapshot or path_snapshot

        self.share_name = share_name
        self.file_path = file_path.split('/')
        self.file_name = self.file_path[-1]
        self.directory_path = "/".join(self.file_path[:-1])

        self._query_str, credential = self._format_query_string(
            sas_token, credential, share_snapshot=self.snapshot)
        super(FileClient, self).__init__(parsed_url, service='file', credential=credential, **kwargs)
        self._client = AzureFileStorage(version=VERSION, url=self.url, pipeline=self._pipeline)

    @classmethod
    def from_file_url(
            cls, file_url,  # type: str
            snapshot=None,  # type: Optional[Union[str, Dict[str, Any]]]
            credential=None,  # type: Optional[Any]
            **kwargs  # type: Any
        ):
        # type: (...) -> FileClient
        """A client to interact with a specific file, although that file may not yet exist.

        :param str file_url: The full URI to the file.
        :param str snapshot:
            An optional file snapshot on which to operate.
        :param credential:
            The credential with which to authenticate. This is optional if the
            account URL already has a SAS token. The value can be a SAS token string or an account
            shared access key.
        """
        try:
            if not file_url.lower().startswith('http'):
                file_url = "https://" + file_url
        except AttributeError:
            raise ValueError("File URL must be a string.")
        parsed_url = urlparse(file_url.rstrip('/'))

        if not (parsed_url.netloc and parsed_url.path):
            raise ValueError("Invalid URL: {}".format(file_url))
        account_url = parsed_url.netloc.rstrip('/') + "?" + parsed_url.query

        path_share, _, path_file = parsed_url.path.lstrip('/').partition('/')
        path_snapshot, _ = parse_query(parsed_url.query)
        snapshot = snapshot or path_snapshot
        share_name = unquote(path_share)
        file_path = [unquote(p) for p in path_file.split('/')]
        return cls(account_url, share_name, file_path, snapshot, credential, **kwargs)

    def _format_url(self, hostname):
        """Format the endpoint URL according to the current location
        mode hostname.
        """
        share_name = self.share_name
        if isinstance(share_name, six.text_type):
            share_name = share_name.encode('UTF-8')
        return "{}://{}/{}/{}{}".format(
            self.scheme,
            hostname,
            quote(share_name),
            "/".join([quote(p, safe='~') for p in self.file_path]),
            self._query_str)

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            share_name=None, # type: str
            file_path=None, # type: Optional[str]
            snapshot=None,  # type: Optional[Union[str, Dict[str, Any]]]
            credential=None,  # type: Optional[Any]
            **kwargs # type: Any
        ):
        # type: (...) -> FileClient
        """Create FileClient from a Connection String.

        :param str conn_str:
            A connection string to an Azure Storage account.
        :param share_name: The share. This can either be the name of the share,
            or an instance of ShareProperties
        :type share_name: str or ~azure.storage.file.ShareProperties
        :param str file_path:
            The file path.
        :param str snapshot:
            An optional file snapshot on which to operate.
        :param credential:
            The credential with which to authenticate. This is optional if the
            account URL already has a SAS token. The value can be a SAS token string or an account
            shared access key.

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_file_samples_hello_world.py
                :start-after: [START create_file_client]
                :end-before: [END create_file_client]
                :language: python
                :dedent: 12
                :caption: Creates the file client with connection string.
        """
        account_url, secondary, credential = parse_connection_str(conn_str, credential, 'file')
        if 'secondary_hostname' not in kwargs:
            kwargs['secondary_hostname'] = secondary
        return cls(
            account_url, share_name=share_name, file_path=file_path, snapshot=snapshot, credential=credential, **kwargs)

    def generate_shared_access_signature(
            self, permission=None,  # type: Optional[Union[FileSasPermissions, str]]
            expiry=None,  # type: Optional[Union[datetime, str]]
            start=None,  # type: Optional[Union[datetime, str]]
            policy_id=None,  # type: Optional[str]
            ip=None,  # type: Optional[str]
            **kwargs # type: Any
        ):
        # type: (...) -> str
        """Generates a shared access signature for the file.

        Use the returned signature with the credential parameter of any FileServiceClient,
        ShareClient, DirectoryClient, or FileClient.

        :param ~azure.storage.file.FileSasPermissions permission:
            The permissions associated with the shared access signature. The
            user is restricted to operations allowed by the permissions.
            Permissions must be ordered read, write, delete, list.
            Required unless an id is given referencing a stored access policy
            which contains this field. This field must be omitted if it has been
            specified in an associated stored access policy.
        :param expiry:
            The time at which the shared access signature becomes invalid.
            Required unless an id is given referencing a stored access policy
            which contains this field. This field must be omitted if it has
            been specified in an associated stored access policy. Azure will always
            convert values to UTC. If a date is passed in without timezone info, it
            is assumed to be UTC.
        :type expiry: ~datetime.datetime or str
        :param start:
            The time at which the shared access signature becomes valid. If
            omitted, start time for this call is assumed to be the time when the
            storage service receives the request. Azure will always convert values
            to UTC. If a date is passed in without timezone info, it is assumed to
            be UTC.
        :type start: ~datetime.datetime or str
        :param str policy_id:
            A unique value up to 64 characters in length that correlates to a
            stored access policy.
        :param str ip:
            Specifies an IP address or a range of IP addresses from which to accept requests.
            If the IP address from which the request originates does not match the IP address
            or address range specified on the SAS token, the request is not authenticated.
            For example, specifying sip=168.1.5.65 or sip=168.1.5.60-168.1.5.70 on the SAS
            restricts the request to those IP addresses.
        :keyword str protocol:
            Specifies the protocol permitted for a request made. The default value is https.
        :keyword str cache_control:
            Response header value for Cache-Control when resource is accessed
            using this shared access signature.
        :keyword str content_disposition:
            Response header value for Content-Disposition when resource is accessed
            using this shared access signature.
        :keyword str content_encoding:
            Response header value for Content-Encoding when resource is accessed
            using this shared access signature.
        :keyword str content_language:
            Response header value for Content-Language when resource is accessed
            using this shared access signature.
        :keyword str content_type:
            Response header value for Content-Type when resource is accessed
            using this shared access signature.
        :keyword str protocol:
            Specifies the protocol permitted for a request made. The default value is https.
        :return: A Shared Access Signature (sas) token.
        :rtype: str
        """
        protocol = kwargs.pop('protocol', None)
        cache_control = kwargs.pop('cache_control', None)
        content_disposition = kwargs.pop('content_disposition', None)
        content_encoding = kwargs.pop('content_encoding', None)
        content_language = kwargs.pop('content_language', None)
        content_type = kwargs.pop('content_type', None)

        if not hasattr(self.credential, 'account_key') or not self.credential.account_key:
            raise ValueError("No account SAS key available.")
        sas = FileSharedAccessSignature(self.credential.account_name, self.credential.account_key)
        if len(self.file_path) > 1:
            file_path = '/'.join(self.file_path[:-1])
        else:
            file_path = None # type: ignore
        return sas.generate_file( # type: ignore
            share_name=self.share_name,
            directory_name=file_path,
            file_name=self.file_name,
            permission=permission,
            expiry=expiry,
            start=start,
            policy_id=policy_id,
            ip=ip,
            protocol=protocol,
            cache_control=cache_control,
            content_disposition=content_disposition,
            content_encoding=content_encoding,
            content_language=content_language,
            content_type=content_type)

    @distributed_trace
    def create_file(  # type: ignore
            self, size,  # type: int
            file_attributes="none",  # type: Union[str, NTFSAttributes]
            file_creation_time="now",  # type: Union[str, datetime]
            file_last_write_time="now",  # type: Union[str, datetime]
            file_permission=None,   # type: Optional[str]
            permission_key=None,  # type: Optional[str]
            **kwargs  # type: Any
    ):
        # type: (...) -> Dict[str, Any]
        """Creates a new file.

        Note that it only initializes the file with no content.

        :param int size: Specifies the maximum size for the file,
            up to 1 TB.
        :param file_attributes:
            The file system attributes for files and directories.
            If not set, the default value would be "None" and the attributes will be set to "Archive".
            Here is an example for when the var type is str: 'Temporary|Archive'.
            file_attributes value is not case sensitive.
        :type file_attributes: str or :class:`~azure.storage.file.NTFSAttributes`
        :param file_creation_time: Creation time for the file
            Default value: Now.
        :type file_creation_time: str or ~datetime.datetime
        :param file_last_write_time: Last write time for the file
            Default value: Now.
        :type file_last_write_time: str or ~datetime.datetime
        :param file_permission: If specified the permission (security
            descriptor) shall be set for the directory/file. This header can be
            used if Permission size is <= 8KB, else x-ms-file-permission-key
            header shall be used. Default value: Inherit. If SDDL is specified as
            input, it must have owner, group and dacl. Note: Only one of the
            x-ms-file-permission or x-ms-file-permission-key should be specified.
        :type file_permission: str
        :param permission_key: Key of the permission to be set for the
            directory/file. Note: Only one of the x-ms-file-permission or
            x-ms-file-permission-key should be specified.
        :type permission_key: str
        :keyword ~azure.storage.file.ContentSettings content_settings:
            ContentSettings object used to set file properties.
        :keyword metadata:
            Name-value pairs associated with the file as metadata.
        :type metadata: dict(str, str)
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: File-updated property dict (Etag and last modified).
        :rtype: dict(str, Any)

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_file_samples_file.py
                :start-after: [START create_file]
                :end-before: [END create_file]
                :language: python
                :dedent: 12
                :caption: Create a file.
        """
        content_settings = kwargs.pop('content_settings', None)
        metadata = kwargs.pop('metadata', None)
        timeout = kwargs.pop('timeout', None)
        if self.require_encryption and not self.key_encryption_key:
            raise ValueError("Encryption required but no key was provided.")

        headers = kwargs.pop('headers', {})
        headers.update(add_metadata_headers(metadata))
        file_http_headers = None
        if content_settings:
            file_http_headers = FileHTTPHeaders(
                file_cache_control=content_settings.cache_control,
                file_content_type=content_settings.content_type,
                file_content_md5=bytearray(content_settings.content_md5) if content_settings.content_md5 else None,
                file_content_encoding=content_settings.content_encoding,
                file_content_language=content_settings.content_language,
                file_content_disposition=content_settings.content_disposition
            )
        file_permission = _get_file_permission(file_permission, permission_key, 'Inherit')
        try:
            return self._client.file.create(  # type: ignore
                file_content_length=size,
                metadata=metadata,
                file_attributes=_str(file_attributes),
                file_creation_time=_datetime_to_str(file_creation_time),
                file_last_write_time=_datetime_to_str(file_last_write_time),
                file_permission=file_permission,
                file_permission_key=permission_key,
                file_http_headers=file_http_headers,
                headers=headers,
                timeout=timeout,
                cls=return_response_headers,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def upload_file(
            self, data,  # type: Any
            length=None,  # type: Optional[int]
            file_attributes="none",  # type: Union[str, NTFSAttributes]
            file_creation_time="now",  # type: Union[str, datetime]
            file_last_write_time="now",  # type: Union[str, datetime]
            file_permission=None,  # type: Optional[str]
            permission_key=None,  # type: Optional[str]
            **kwargs  # type: Any
        ):
        # type: (...) -> Dict[str, Any]
        """Uploads a new file.

        :param Any data:
            Content of the file.
        :param int length:
            Length of the file in bytes. Specify its maximum size, up to 1 TiB.
        :param file_attributes:
            The file system attributes for files and directories.
            If not set, the default value would be "None" and the attributes will be set to "Archive".
            Here is an example for when the var type is str: 'Temporary|Archive'.
            file_attributes value is not case sensitive.
        :type file_attributes: str or ~azure.storage.file.NTFSAttributes
        :param file_creation_time: Creation time for the file
            Default value: Now.
        :type file_creation_time: str or ~datetime.datetime
        :param file_last_write_time: Last write time for the file
            Default value: Now.
        :type file_last_write_time: str or ~datetime.datetime
        :param file_permission: If specified the permission (security
            descriptor) shall be set for the directory/file. This header can be
            used if Permission size is <= 8KB, else x-ms-file-permission-key
            header shall be used. Default value: Inherit. If SDDL is specified as
            input, it must have owner, group and dacl. Note: Only one of the
            x-ms-file-permission or x-ms-file-permission-key should be specified.
        :type file_permission: str
        :param permission_key: Key of the permission to be set for the
            directory/file. Note: Only one of the x-ms-file-permission or
            x-ms-file-permission-key should be specified.
        :type permission_key: str
        :keyword metadata:
            Name-value pairs associated with the file as metadata.
        :type metadata: dict(str, str)
        :keyword ~azure.storage.file.ContentSettings content_settings:
            ContentSettings object used to set file properties.
        :keyword bool validate_content:
            If true, calculates an MD5 hash for each range of the file. The storage
            service checks the hash of the content that has arrived with the hash
            that was sent. This is primarily valuable for detecting bitflips on
            the wire if using http instead of https as https (the default) will
            already validate. Note that this MD5 hash is not stored with the
            file.
        :keyword int max_concurrency:
            Maximum number of parallel connections to use.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :keyword str encoding:
            Defaults to UTF-8.
        :returns: File-updated property dict (Etag and last modified).
        :rtype: dict(str, Any)

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_file_samples_file.py
                :start-after: [START upload_file]
                :end-before: [END upload_file]
                :language: python
                :dedent: 12
                :caption: Upload a file.
        """
        metadata = kwargs.pop('metadata', None)
        content_settings = kwargs.pop('content_settings', None)
        max_concurrency = kwargs.pop('max_concurrency', 1)
        validate_content = kwargs.pop('validate_content', False)
        timeout = kwargs.pop('timeout', None)
        encoding = kwargs.pop('encoding', 'UTF-8')
        if self.require_encryption or (self.key_encryption_key is not None):
            raise ValueError("Encryption not supported.")

        if isinstance(data, six.text_type):
            data = data.encode(encoding)
        if length is None:
            length = get_length(data)
        if isinstance(data, bytes):
            data = data[:length]

        if isinstance(data, bytes):
            stream = BytesIO(data)
        elif hasattr(data, 'read'):
            stream = data
        elif hasattr(data, '__iter__'):
            stream = IterStreamer(data, encoding=encoding) # type: ignore
        else:
            raise TypeError("Unsupported data type: {}".format(type(data)))
        return _upload_file_helper( # type: ignore
            self,
            stream,
            length,
            metadata,
            content_settings,
            validate_content,
            timeout,
            max_concurrency,
            self._config,
            file_attributes=file_attributes,
            file_creation_time=file_creation_time,
            file_last_write_time=file_last_write_time,
            file_permission=file_permission,
            file_permission_key=permission_key,
            **kwargs)

    @distributed_trace
    def start_copy_from_url(
            self, source_url, # type: str
            **kwargs # type: Any
        ):
        # type: (...) -> Any
        """Initiates the copying of data from a source URL into the file
        referenced by the client.

        The status of this copy operation can be found using the `get_properties`
        method.

        :param str source_url:
            Specifies the URL of the source file.
        :keyword metadata:
            Name-value pairs associated with the file as metadata.
        :type metadata: dict(str, str)
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: dict(str, Any)

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_file_samples_file.py
                :start-after: [START copy_file_from_url]
                :end-before: [END copy_file_from_url]
                :language: python
                :dedent: 12
                :caption: Copy a file from a URL
        """
        metadata = kwargs.pop('metadata', None)
        timeout = kwargs.pop('timeout', None)
        headers = kwargs.pop('headers', {})
        headers.update(add_metadata_headers(metadata))

        try:
            return self._client.file.start_copy(
                source_url,
                timeout=timeout,
                metadata=metadata,
                headers=headers,
                cls=return_response_headers,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    def abort_copy(self, copy_id, **kwargs):
        # type: (Union[str, FileProperties], Any) -> Dict[str, Any]
        """Abort an ongoing copy operation.

        This will leave a destination file with zero length and full metadata.
        This will raise an error if the copy operation has already ended.

        :param copy_id:
            The copy operation to abort. This can be either an ID, or an
            instance of FileProperties.
        :type copy_id: str or ~azure.storage.file.FileProperties
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: None
        """
        timeout = kwargs.pop('timeout', None)
        try:
            copy_id = copy_id.copy.id
        except AttributeError:
            try:
                copy_id = copy_id['copy_id']
            except TypeError:
                pass
        try:
            self._client.file.abort_copy(copy_id=copy_id, timeout=timeout, **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def download_file(
            self, offset=None,  # type: Optional[int]
            length=None,  # type: Optional[int]
            **kwargs
        ):
        # type: (...) -> Iterable[bytes]
        """Downloads a file to a stream with automatic chunking.

        :param int offset:
            Start of byte range to use for downloading a section of the file.
            Must be set if length is provided.
        :param int length:
            Number of bytes to read from the stream. This is optional, but
            should be supplied for optimal performance.
        :keyword bool validate_content:
            If true, calculates an MD5 hash for each chunk of the file. The storage
            service checks the hash of the content that has arrived with the hash
            that was sent. This is primarily valuable for detecting bitflips on
            the wire if using http instead of https as https (the default) will
            already validate. Note that this MD5 hash is not stored with the
            file. Also note that if enabled, the memory-efficient upload algorithm
            will not be used, because computing the MD5 hash requires buffering
            entire blocks, and doing so defeats the purpose of the memory-efficient algorithm.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: A iterable data generator (stream)

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_file_samples_file.py
                :start-after: [START download_file]
                :end-before: [END download_file]
                :language: python
                :dedent: 12
                :caption: Download a file.
        """
        validate_content = kwargs.pop('validate_content', False)
        timeout = kwargs.pop('timeout', None)
        if self.require_encryption or (self.key_encryption_key is not None):
            raise ValueError("Encryption not supported.")
        if length is not None and offset is None:
            raise ValueError("Offset value must not be None if length is set.")

        return StorageStreamDownloader(
            client=self._client.file,
            config=self._config,
            offset=offset,
            length=length,
            validate_content=validate_content,
            encryption_options=None,
            extra_properties={
                'share': self.share_name,
                'name': self.file_name,
                'path': '/'.join(self.file_path),
            },
            cls=deserialize_file_stream,
            timeout=timeout,
            **kwargs)

    @distributed_trace
    def delete_file(self, **kwargs):
        # type: (Any) -> None
        """Marks the specified file for deletion. The file is
        later deleted during garbage collection.

        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_file_samples_file.py
                :start-after: [START delete_file]
                :end-before: [END delete_file]
                :language: python
                :dedent: 12
                :caption: Delete a file.
        """
        timeout = kwargs.pop('timeout', None)
        try:
            self._client.file.delete(timeout=timeout, **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def get_file_properties(self, **kwargs):
        # type: (Any) -> FileProperties
        """Returns all user-defined metadata, standard HTTP properties, and
        system properties for the file.

        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: ~azure.storage.file.FileProperties
        """
        timeout = kwargs.pop('timeout', None)
        try:
            file_props = self._client.file.get_properties(
                sharesnapshot=self.snapshot,
                timeout=timeout,
                cls=deserialize_file_properties,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)
        file_props.name = self.file_name
        file_props.share = self.share_name
        file_props.snapshot = self.snapshot
        file_props.path = '/'.join(self.file_path)
        return file_props # type: ignore

    @distributed_trace
    def set_http_headers(self, content_settings,  # type: ContentSettings
                         file_attributes="preserve",  # type: Union[str, NTFSAttributes]
                         file_creation_time="preserve",  # type: Union[str, datetime]
                         file_last_write_time="preserve",  # type: Union[str, datetime]
                         file_permission=None,  # type: Optional[str]
                         permission_key=None,  # type: Optional[str]
                         **kwargs  # Any
                         ):  # type: ignore
        # type: (ContentSettings, Optional[int], Optional[Any]) -> Dict[str, Any]
        """Sets HTTP headers on the file.

        :param ~azure.storage.file.ContentSettings content_settings:
            ContentSettings object used to set file properties.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :param file_attributes:
            The file system attributes for files and directories.
            If not set, indicates preservation of existing values.
            Here is an example for when the var type is str: 'Temporary|Archive'
        :type file_attributes: str or :class:`~azure.storage.file.NTFSAttributes`
        :param file_creation_time: Creation time for the file
            Default value: Now.
        :type file_creation_time: str or ~datetime.datetime
        :param file_last_write_time: Last write time for the file
            Default value: Now.
        :type file_last_write_time: str or ~datetime.datetime
        :param file_permission: If specified the permission (security
            descriptor) shall be set for the directory/file. This header can be
            used if Permission size is <= 8KB, else x-ms-file-permission-key
            header shall be used. Default value: Inherit. If SDDL is specified as
            input, it must have owner, group and dacl. Note: Only one of the
            x-ms-file-permission or x-ms-file-permission-key should be specified.
        :type file_permission: str
        :param permission_key: Key of the permission to be set for the
            directory/file. Note: Only one of the x-ms-file-permission or
            x-ms-file-permission-key should be specified.
        :type permission_key: str
        :returns: File-updated property dict (Etag and last modified).
        :rtype: dict(str, Any)
        """
        timeout = kwargs.pop('timeout', None)
        file_content_length = kwargs.pop('size', None)
        file_http_headers = FileHTTPHeaders(
            file_cache_control=content_settings.cache_control,
            file_content_type=content_settings.content_type,
            file_content_md5=bytearray(content_settings.content_md5) if content_settings.content_md5 else None,
            file_content_encoding=content_settings.content_encoding,
            file_content_language=content_settings.content_language,
            file_content_disposition=content_settings.content_disposition
        )
        file_permission = _get_file_permission(file_permission, permission_key, 'preserve')
        try:
            return self._client.file.set_http_headers(  # type: ignore
                file_content_length=file_content_length,
                file_http_headers=file_http_headers,
                file_attributes=_str(file_attributes),
                file_creation_time=_datetime_to_str(file_creation_time),
                file_last_write_time=_datetime_to_str(file_last_write_time),
                file_permission=file_permission,
                file_permission_key=permission_key,
                timeout=timeout,
                cls=return_response_headers,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def set_file_metadata(self, metadata=None, **kwargs): # type: ignore
        #type: (Optional[Dict[str, Any]], Any) -> Dict[str, Any]
        """Sets user-defined metadata for the specified file as one or more
        name-value pairs.

        Each call to this operation replaces all existing metadata
        attached to the file. To remove all metadata from the file,
        call this operation with no metadata dict.

        :param metadata:
            Name-value pairs associated with the file as metadata.
        :type metadata: dict(str, str)
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: File-updated property dict (Etag and last modified).
        :rtype: dict(str, Any)
        """
        timeout = kwargs.pop('timeout', None)
        headers = kwargs.pop('headers', {})
        headers.update(add_metadata_headers(metadata)) # type: ignore
        try:
            return self._client.file.set_metadata( # type: ignore
                timeout=timeout,
                cls=return_response_headers,
                headers=headers,
                metadata=metadata,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def upload_range(  # type: ignore
            self, data,  # type: bytes
            start_range,  # type: int
            end_range,  # type: int
            **kwargs
        ):
        # type: (...) -> Dict[str, Any]
        """Upload a range of bytes to a file.

        :param bytes data:
            The data to upload.
        :param int start_range:
            Start of byte range to use for uploading a section of the file.
            The range can be up to 4 MB in size.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will upload first 512 bytes of file.
        :param int end_range:
            End of byte range to use for uploading a section of the file.
            The range can be up to 4 MB in size.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will upload first 512 bytes of file.
        :keyword bool validate_content:
            If true, calculates an MD5 hash of the page content. The storage
            service checks the hash of the content that has arrived
            with the hash that was sent. This is primarily valuable for detecting
            bitflips on the wire if using http instead of https as https (the default)
            will already validate. Note that this MD5 hash is not stored with the
            file.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :keyword str encoding:
            Defaults to UTF-8.
        :returns: File-updated property dict (Etag and last modified).
        :rtype: Dict[str, Any]
        """
        validate_content = kwargs.pop('validate_content', False)
        timeout = kwargs.pop('timeout', None)
        encoding = kwargs.pop('encoding', 'UTF-8')
        if self.require_encryption or (self.key_encryption_key is not None):
            raise ValueError("Encryption not supported.")
        if isinstance(data, six.text_type):
            data = data.encode(encoding)

        content_range = 'bytes={0}-{1}'.format(start_range, end_range)
        content_length = end_range - start_range + 1
        try:
            return self._client.file.upload_range( # type: ignore
                range=content_range,
                content_length=content_length,
                optionalbody=data,
                timeout=timeout,
                validate_content=validate_content,
                cls=return_response_headers,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @staticmethod
    def _upload_range_from_url_options(source_url,  # type: str
                                       range_start,  # type: int
                                       range_end,  # type: int
                                       source_range_start,  # type: int
                                       **kwargs
                                       ):
        # type: (...) -> Dict[str, Any]

        if range_start is None or range_end is None or source_range_start is None:
            raise ValueError("start_range must be specified")

        # Format range
        destination_range = 'bytes={0}-{1}'.format(range_start, range_end)
        source_range = 'bytes={0}-{1}'.format(source_range_start, source_range_start + (range_end - range_start))

        options = {
            'copy_source': source_url,
            'content_length': 0,
            'source_range': source_range,
            'range': destination_range,
            'timeout': kwargs.pop('timeout', None),
            'cls': return_response_headers}
        options.update(kwargs)
        return options

    @distributed_trace
    def upload_range_from_url(self, source_url,  # type: str
                              range_start,  # type: int
                              range_end,  # type: int
                              source_range_start,  # type: int
                              **kwargs  # type: Any
                              ):
        # type: (str, int, int, int, **Any) -> Dict[str, Any]
        '''
        Writes the bytes from one Azure File endpoint into the specified range of another Azure File endpoint.

        :param int range_start:
            Start of byte range to use for updating a section of the file.
            The range can be up to 4 MB in size.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will download first 512 bytes of file.
        :param int range_end:
            End of byte range to use for updating a section of the file.
            The range can be up to 4 MB in size.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will download first 512 bytes of file.
        :param str source_url:
            A URL of up to 2 KB in length that specifies an Azure file or blob.
            The value should be URL-encoded as it would appear in a request URI.
            If the source is in another account, the source must either be public
            or must be authenticated via a shared access signature. If the source
            is public, no authentication is required.
            Examples:
            https://myaccount.file.core.windows.net/myshare/mydir/myfile
            https://otheraccount.file.core.windows.net/myshare/mydir/myfile?sastoken
        :param int source_range_start:
            Start of byte range to use for updating a section of the file.
            The range can be up to 4 MB in size.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will download first 512 bytes of file.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        '''
        options = self._upload_range_from_url_options(
            source_url=source_url,
            range_start=range_start,
            range_end=range_end,
            source_range_start=source_range_start,
            **kwargs
        )
        try:
            return self._client.file.upload_range_from_url(**options)  # type: ignore
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def get_ranges( # type: ignore
            self, start_range=None, # type: Optional[int]
            end_range=None, # type: Optional[int]
            **kwargs
        ):
        # type: (...) -> List[dict[str, int]]
        """Returns the list of valid ranges of a file.

        :param int start_range:
            Specifies the start offset of bytes over which to get ranges.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will download first 512 bytes of file.
        :param int end_range:
            Specifies the end offset of bytes over which to get ranges.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will download first 512 bytes of file.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: A list of valid ranges.
        :rtype: List[dict[str, int]]
        """
        timeout = kwargs.pop('timeout', None)
        if self.require_encryption or (self.key_encryption_key is not None):
            raise ValueError("Unsupported method for encryption.")

        content_range = None
        if start_range is not None:
            if end_range is not None:
                content_range = 'bytes={0}-{1}'.format(start_range, end_range)
            else:
                content_range = 'bytes={0}-'.format(start_range)
        try:
            ranges = self._client.file.get_range_list(
                sharesnapshot=self.snapshot,
                timeout=timeout,
                range=content_range,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)
        return [{'start': b.start, 'end': b.end} for b in ranges]

    @distributed_trace
    def clear_range( # type: ignore
            self, start_range,  # type: int
            end_range,  # type: int
            **kwargs
        ):
        # type: (...) -> Dict[str, Any]
        """Clears the specified range and releases the space used in storage for
        that range.

        :param int start_range:
            Start of byte range to use for clearing a section of the file.
            The range can be up to 4 MB in size.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will download first 512 bytes of file.
        :param int end_range:
            End of byte range to use for clearing a section of the file.
            The range can be up to 4 MB in size.
            The start_range and end_range params are inclusive.
            Ex: start_range=0, end_range=511 will download first 512 bytes of file.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: File-updated property dict (Etag and last modified).
        :rtype: Dict[str, Any]
        """
        timeout = kwargs.pop('timeout', None)
        if self.require_encryption or (self.key_encryption_key is not None):
            raise ValueError("Unsupported method for encryption.")

        if start_range is None or start_range % 512 != 0:
            raise ValueError("start_range must be an integer that aligns with 512 file size")
        if end_range is None or end_range % 512 != 511:
            raise ValueError("end_range must be an integer that aligns with 512 file size")
        content_range = 'bytes={0}-{1}'.format(start_range, end_range)
        try:
            return self._client.file.upload_range( # type: ignore
                timeout=timeout,
                cls=return_response_headers,
                content_length=0,
                file_range_write="clear",
                range=content_range,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def resize_file(self, size, **kwargs): # type: ignore
        # type: (int, Any) -> Dict[str, Any]
        """Resizes a file to the specified size.

        :param int size:
            Size to resize file to (in bytes)
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: File-updated property dict (Etag and last modified).
        :rtype: Dict[str, Any]
        """
        timeout = kwargs.pop('timeout', None)
        try:
            return self._client.file.set_http_headers( # type: ignore
                file_content_length=size,
                file_attributes="preserve",
                file_creation_time="preserve",
                file_last_write_time="preserve",
                file_permission="preserve",
                cls=return_response_headers,
                timeout=timeout,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def list_handles(self, **kwargs):
        # type: (int, Any) -> ItemPaged[Handle]
        """Lists handles for file.

        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: An auto-paging iterable of HandleItem
        :rtype: ~azure.core.paging.ItemPaged[~azure.storage.file.HandleItem]
        """
        timeout = kwargs.pop('timeout', None)
        results_per_page = kwargs.pop('results_per_page', None)
        command = functools.partial(
            self._client.file.list_handles,
            sharesnapshot=self.snapshot,
            timeout=timeout,
            **kwargs)
        return ItemPaged(
            command, results_per_page=results_per_page,
            page_iterator_class=HandlesPaged)

    @distributed_trace
    def close_handle(self, handle, **kwargs):
        # type: (Union[str, HandleItem], Any) -> int
        """Close an open file handle.

        :param handle:
            A specific handle to close.
        :type handle: str or ~azure.storage.file.Handle
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns:
            The number of handles closed (this may be 0 if the specified handle was not found).
        :rtype: int
        """
        try:
            handle_id = handle.id # type: ignore
        except AttributeError:
            handle_id = handle
        if handle_id == '*':
            raise ValueError("Handle ID '*' is not supported. Use 'close_all_handles' instead.")
        try:
            response = self._client.file.force_close_handles(
                handle_id,
                marker=None,
                sharesnapshot=self.snapshot,
                cls=return_response_headers,
                **kwargs
            )
            return response.get('number_of_handles_closed', 0)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def close_all_handles(self, **kwargs):
        # type: (Any) -> int
        """Close any open file handles.

        This operation will block until the service has closed all open handles.

        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: The total number of handles closed.
        :rtype: int
        """
        timeout = kwargs.pop('timeout', None)
        start_time = time.time()

        try_close = True
        continuation_token = None
        total_handles = 0
        while try_close:
            try:
                response = self._client.file.force_close_handles(
                    handle_id='*',
                    timeout=timeout,
                    marker=continuation_token,
                    sharesnapshot=self.snapshot,
                    cls=return_response_headers,
                    **kwargs
                )
            except StorageErrorException as error:
                process_storage_error(error)
            continuation_token = response.get('marker')
            try_close = bool(continuation_token)
            total_handles += response.get('number_of_handles_closed')
            if timeout:
                timeout = max(0, timeout - (time.time() - start_time))
        return total_handles
