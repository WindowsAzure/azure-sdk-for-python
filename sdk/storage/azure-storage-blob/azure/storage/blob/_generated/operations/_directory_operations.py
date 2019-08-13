# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

import uuid
from azure.core.exceptions import map_error

from .. import models


class DirectoryOperations(object):
    """DirectoryOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar resource: . Constant value: "directory".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.resource = "directory"

        self._config = config

    def create(self, timeout=None, directory_properties=None, posix_permissions=None, posix_umask=None, request_id=None, directory_http_headers=None, lease_access_conditions=None, modified_access_conditions=None, cls=None, **kwargs):
        """Create a directory. By default, the destination is overwritten and if
        the destination already exists and has a lease the lease is broken.
        This operation supports conditional HTTP requests.  For more
        information, see [Specifying Conditional Headers for Blob Service
        Operations](https://docs.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations).
        To fail if the destination already exists, use a conditional request
        with If-None-Match: "*".

        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param directory_properties: Optional.  User-defined properties to be
         stored with the file or directory, in the format of a comma-separated
         list of name and value pairs "n1=v1, n2=v2, ...", where each value is
         base64 encoded.
        :type directory_properties: str
        :param posix_permissions: Optional and only valid if Hierarchical
         Namespace is enabled for the account. Sets POSIX access permissions
         for the file owner, the file owning group, and others. Each class may
         be granted read, write, or execute permission.  The sticky bit is also
         supported.  Both symbolic (rwxrw-rw-) and 4-digit octal notation (e.g.
         0766) are supported.
        :type posix_permissions: str
        :param posix_umask: Only valid if Hierarchical Namespace is enabled
         for the account. This umask restricts permission settings for file and
         directory, and will only be applied when default Acl does not exist in
         parent directory. If the umask bit has set, it means that the
         corresponding permission will be disabled. Otherwise the corresponding
         permission will be determined by the permission. A 4-digit octal
         notation (e.g. 0022) is supported here. If no umask was specified, a
         default umask - 0027 will be used.
        :type posix_umask: str
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param directory_http_headers: Additional parameters for the operation
        :type directory_http_headers: ~blob.models.DirectoryHttpHeaders
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions: ~blob.models.LeaseAccessConditions
        :param modified_access_conditions: Additional parameters for the
         operation
        :type modified_access_conditions:
         ~blob.models.ModifiedAccessConditions
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises:
         :class:`DataLakeStorageErrorException<blob.models.DataLakeStorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        cache_control = None
        if directory_http_headers is not None:
            cache_control = directory_http_headers.cache_control
        content_type = None
        if directory_http_headers is not None:
            content_type = directory_http_headers.content_type
        content_encoding = None
        if directory_http_headers is not None:
            content_encoding = directory_http_headers.content_encoding
        content_language = None
        if directory_http_headers is not None:
            content_language = directory_http_headers.content_language
        content_disposition = None
        if directory_http_headers is not None:
            content_disposition = directory_http_headers.content_disposition
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id
        if_modified_since = None
        if modified_access_conditions is not None:
            if_modified_since = modified_access_conditions.if_modified_since
        if_unmodified_since = None
        if modified_access_conditions is not None:
            if_unmodified_since = modified_access_conditions.if_unmodified_since
        if_match = None
        if modified_access_conditions is not None:
            if_match = modified_access_conditions.if_match
        if_none_match = None
        if modified_access_conditions is not None:
            if_none_match = modified_access_conditions.if_none_match

        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        query_parameters['resource'] = self._serialize.query("self.resource", self.resource, 'str')

        # Construct headers
        header_parameters = {}
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if directory_properties is not None:
            header_parameters['x-ms-properties'] = self._serialize.header("directory_properties", directory_properties, 'str')
        if posix_permissions is not None:
            header_parameters['x-ms-permissions'] = self._serialize.header("posix_permissions", posix_permissions, 'str')
        if posix_umask is not None:
            header_parameters['x-ms-umask'] = self._serialize.header("posix_umask", posix_umask, 'str')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if cache_control is not None:
            header_parameters['x-ms-cache-control'] = self._serialize.header("cache_control", cache_control, 'str')
        if content_type is not None:
            header_parameters['x-ms-content-type'] = self._serialize.header("content_type", content_type, 'str')
        if content_encoding is not None:
            header_parameters['x-ms-content-encoding'] = self._serialize.header("content_encoding", content_encoding, 'str')
        if content_language is not None:
            header_parameters['x-ms-content-language'] = self._serialize.header("content_language", content_language, 'str')
        if content_disposition is not None:
            header_parameters['x-ms-content-disposition'] = self._serialize.header("content_disposition", content_disposition, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')
        if if_modified_since is not None:
            header_parameters['If-Modified-Since'] = self._serialize.header("if_modified_since", if_modified_since, 'rfc-1123')
        if if_unmodified_since is not None:
            header_parameters['If-Unmodified-Since'] = self._serialize.header("if_unmodified_since", if_unmodified_since, 'rfc-1123')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.DataLakeStorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'ETag': self._deserialize('str', response.headers.get('ETag')),
                'Last-Modified': self._deserialize('rfc-1123', response.headers.get('Last-Modified')),
                'x-ms-client-request-id': self._deserialize('str', response.headers.get('x-ms-client-request-id')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Content-Length': self._deserialize('long', response.headers.get('Content-Length')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
            }
            return cls(response, None, response_headers)
    create.metadata = {'url': '/{filesystem}/{path}'}

    def rename(self, rename_source, timeout=None, marker=None, directory_properties=None, posix_permissions=None, posix_umask=None, source_lease_id=None, request_id=None, directory_http_headers=None, lease_access_conditions=None, modified_access_conditions=None, source_modified_access_conditions=None, cls=None, **kwargs):
        """Rename a directory. By default, the destination is overwritten and if
        the destination already exists and has a lease the lease is broken.
        This operation supports conditional HTTP requests. For more
        information, see [Specifying Conditional Headers for Blob Service
        Operations](https://docs.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations).
        To fail if the destination already exists, use a conditional request
        with If-None-Match: "*".

        :param rename_source: The file or directory to be renamed. The value
         must have the following format: "/{filesysystem}/{path}".  If
         "x-ms-properties" is specified, the properties will overwrite the
         existing properties; otherwise, the existing properties will be
         preserved.
        :type rename_source: str
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param marker: When renaming a directory, the number of paths that are
         renamed with each invocation is limited.  If the number of paths to be
         renamed exceeds this limit, a continuation token is returned in this
         response header.  When a continuation token is returned in the
         response, it must be specified in a subsequent invocation of the
         rename operation to continue renaming the directory.
        :type marker: str
        :param directory_properties: Optional.  User-defined properties to be
         stored with the file or directory, in the format of a comma-separated
         list of name and value pairs "n1=v1, n2=v2, ...", where each value is
         base64 encoded.
        :type directory_properties: str
        :param posix_permissions: Optional and only valid if Hierarchical
         Namespace is enabled for the account. Sets POSIX access permissions
         for the file owner, the file owning group, and others. Each class may
         be granted read, write, or execute permission.  The sticky bit is also
         supported.  Both symbolic (rwxrw-rw-) and 4-digit octal notation (e.g.
         0766) are supported.
        :type posix_permissions: str
        :param posix_umask: Only valid if Hierarchical Namespace is enabled
         for the account. This umask restricts permission settings for file and
         directory, and will only be applied when default Acl does not exist in
         parent directory. If the umask bit has set, it means that the
         corresponding permission will be disabled. Otherwise the corresponding
         permission will be determined by the permission. A 4-digit octal
         notation (e.g. 0022) is supported here. If no umask was specified, a
         default umask - 0027 will be used.
        :type posix_umask: str
        :param source_lease_id: A lease ID for the source path. If specified,
         the source path must have an active lease and the leaase ID must
         match.
        :type source_lease_id: str
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param directory_http_headers: Additional parameters for the operation
        :type directory_http_headers: ~blob.models.DirectoryHttpHeaders
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions: ~blob.models.LeaseAccessConditions
        :param modified_access_conditions: Additional parameters for the
         operation
        :type modified_access_conditions:
         ~blob.models.ModifiedAccessConditions
        :param source_modified_access_conditions: Additional parameters for
         the operation
        :type source_modified_access_conditions:
         ~blob.models.SourceModifiedAccessConditions
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises:
         :class:`DataLakeStorageErrorException<blob.models.DataLakeStorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        cache_control = None
        if directory_http_headers is not None:
            cache_control = directory_http_headers.cache_control
        content_type = None
        if directory_http_headers is not None:
            content_type = directory_http_headers.content_type
        content_encoding = None
        if directory_http_headers is not None:
            content_encoding = directory_http_headers.content_encoding
        content_language = None
        if directory_http_headers is not None:
            content_language = directory_http_headers.content_language
        content_disposition = None
        if directory_http_headers is not None:
            content_disposition = directory_http_headers.content_disposition
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id
        if_modified_since = None
        if modified_access_conditions is not None:
            if_modified_since = modified_access_conditions.if_modified_since
        if_unmodified_since = None
        if modified_access_conditions is not None:
            if_unmodified_since = modified_access_conditions.if_unmodified_since
        if_match = None
        if modified_access_conditions is not None:
            if_match = modified_access_conditions.if_match
        if_none_match = None
        if modified_access_conditions is not None:
            if_none_match = modified_access_conditions.if_none_match
        source_if_modified_since = None
        if source_modified_access_conditions is not None:
            source_if_modified_since = source_modified_access_conditions.source_if_modified_since
        source_if_unmodified_since = None
        if source_modified_access_conditions is not None:
            source_if_unmodified_since = source_modified_access_conditions.source_if_unmodified_since
        source_if_match = None
        if source_modified_access_conditions is not None:
            source_if_match = source_modified_access_conditions.source_if_match
        source_if_none_match = None
        if source_modified_access_conditions is not None:
            source_if_none_match = source_modified_access_conditions.source_if_none_match

        # Construct URL
        url = self.rename.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        if marker is not None:
            query_parameters['continuation'] = self._serialize.query("marker", marker, 'str')
        if self._config.path_rename_mode is not None:
            query_parameters['mode'] = self._serialize.query("self._config.path_rename_mode", self._config.path_rename_mode, 'PathRenameMode')

        # Construct headers
        header_parameters = {}
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        header_parameters['x-ms-rename-source'] = self._serialize.header("rename_source", rename_source, 'str')
        if directory_properties is not None:
            header_parameters['x-ms-properties'] = self._serialize.header("directory_properties", directory_properties, 'str')
        if posix_permissions is not None:
            header_parameters['x-ms-permissions'] = self._serialize.header("posix_permissions", posix_permissions, 'str')
        if posix_umask is not None:
            header_parameters['x-ms-umask'] = self._serialize.header("posix_umask", posix_umask, 'str')
        if source_lease_id is not None:
            header_parameters['x-ms-source-lease-id'] = self._serialize.header("source_lease_id", source_lease_id, 'str')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if cache_control is not None:
            header_parameters['x-ms-cache-control'] = self._serialize.header("cache_control", cache_control, 'str')
        if content_type is not None:
            header_parameters['x-ms-content-type'] = self._serialize.header("content_type", content_type, 'str')
        if content_encoding is not None:
            header_parameters['x-ms-content-encoding'] = self._serialize.header("content_encoding", content_encoding, 'str')
        if content_language is not None:
            header_parameters['x-ms-content-language'] = self._serialize.header("content_language", content_language, 'str')
        if content_disposition is not None:
            header_parameters['x-ms-content-disposition'] = self._serialize.header("content_disposition", content_disposition, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')
        if if_modified_since is not None:
            header_parameters['If-Modified-Since'] = self._serialize.header("if_modified_since", if_modified_since, 'rfc-1123')
        if if_unmodified_since is not None:
            header_parameters['If-Unmodified-Since'] = self._serialize.header("if_unmodified_since", if_unmodified_since, 'rfc-1123')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')
        if source_if_modified_since is not None:
            header_parameters['x-ms-source-if-modified-since'] = self._serialize.header("source_if_modified_since", source_if_modified_since, 'rfc-1123')
        if source_if_unmodified_since is not None:
            header_parameters['x-ms-source-if-unmodified-since'] = self._serialize.header("source_if_unmodified_since", source_if_unmodified_since, 'rfc-1123')
        if source_if_match is not None:
            header_parameters['x-ms-source-if-match'] = self._serialize.header("source_if_match", source_if_match, 'str')
        if source_if_none_match is not None:
            header_parameters['x-ms-source-if-none-match'] = self._serialize.header("source_if_none_match", source_if_none_match, 'str')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.DataLakeStorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'x-ms-continuation': self._deserialize('str', response.headers.get('x-ms-continuation')),
                'ETag': self._deserialize('str', response.headers.get('ETag')),
                'Last-Modified': self._deserialize('rfc-1123', response.headers.get('Last-Modified')),
                'x-ms-client-request-id': self._deserialize('str', response.headers.get('x-ms-client-request-id')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Content-Length': self._deserialize('long', response.headers.get('Content-Length')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
            }
            return cls(response, None, response_headers)
    rename.metadata = {'url': '/{filesystem}/{path}'}

    def delete(self, recursive_directory_delete, timeout=None, marker=None, request_id=None, lease_access_conditions=None, modified_access_conditions=None, cls=None, **kwargs):
        """Deletes the directory.

        :param recursive_directory_delete: If "true", all paths beneath the
         directory will be deleted. If "false" and the directory is non-empty,
         an error occurs.
        :type recursive_directory_delete: bool
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param marker: When renaming a directory, the number of paths that are
         renamed with each invocation is limited.  If the number of paths to be
         renamed exceeds this limit, a continuation token is returned in this
         response header.  When a continuation token is returned in the
         response, it must be specified in a subsequent invocation of the
         rename operation to continue renaming the directory.
        :type marker: str
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions: ~blob.models.LeaseAccessConditions
        :param modified_access_conditions: Additional parameters for the
         operation
        :type modified_access_conditions:
         ~blob.models.ModifiedAccessConditions
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises:
         :class:`DataLakeStorageErrorException<blob.models.DataLakeStorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id
        if_modified_since = None
        if modified_access_conditions is not None:
            if_modified_since = modified_access_conditions.if_modified_since
        if_unmodified_since = None
        if modified_access_conditions is not None:
            if_unmodified_since = modified_access_conditions.if_unmodified_since
        if_match = None
        if modified_access_conditions is not None:
            if_match = modified_access_conditions.if_match
        if_none_match = None
        if modified_access_conditions is not None:
            if_none_match = modified_access_conditions.if_none_match

        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        query_parameters['recursive'] = self._serialize.query("recursive_directory_delete", recursive_directory_delete, 'bool')
        if marker is not None:
            query_parameters['continuation'] = self._serialize.query("marker", marker, 'str')

        # Construct headers
        header_parameters = {}
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')
        if if_modified_since is not None:
            header_parameters['If-Modified-Since'] = self._serialize.header("if_modified_since", if_modified_since, 'rfc-1123')
        if if_unmodified_since is not None:
            header_parameters['If-Unmodified-Since'] = self._serialize.header("if_unmodified_since", if_unmodified_since, 'rfc-1123')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.DataLakeStorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'x-ms-continuation': self._deserialize('str', response.headers.get('x-ms-continuation')),
                'x-ms-client-request-id': self._deserialize('str', response.headers.get('x-ms-client-request-id')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
            }
            return cls(response, None, response_headers)
    delete.metadata = {'url': '/{filesystem}/{path}'}
