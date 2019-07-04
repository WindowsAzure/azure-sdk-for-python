# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------
# pylint: skip-file

from azure.core.exceptions import map_error

from .. import models


class AppendBlobOperations(object):
    """AppendBlobOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar x_ms_blob_type: Specifies the type of blob to create: block blob, page blob, or append blob. Constant value: "AppendBlob".
    :ivar comp: . Constant value: "appendblock".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self._config = config
        self.x_ms_blob_type = "AppendBlob"
        self.comp = "appendblock"

    def create(self, content_length, timeout=None, metadata=None, request_id=None, blob_http_headers=None, lease_access_conditions=None, modified_access_conditions=None, cls=None, **kwargs):
        """The Create Append Blob operation creates a new append blob.

        :param content_length: The length of the request.
        :type content_length: long
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param metadata: Optional. Specifies a user-defined name-value pair
         associated with the blob. If no name-value pairs are specified, the
         operation will copy the metadata from the source blob or file to the
         destination blob. If one or more name-value pairs are specified, the
         destination blob is created with the specified metadata, and metadata
         is not copied from the source blob or file. Note that beginning with
         version 2009-09-19, metadata names must adhere to the naming rules for
         C# identifiers. See Naming and Referencing Containers, Blobs, and
         Metadata for more information.
        :type metadata: str
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param blob_http_headers: Additional parameters for the operation
        :type blob_http_headers: ~blob.models.BlobHTTPHeaders
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
         :class:`StorageErrorException<blob.models.StorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        blob_content_type = None
        if blob_http_headers is not None:
            blob_content_type = blob_http_headers.blob_content_type
        blob_content_encoding = None
        if blob_http_headers is not None:
            blob_content_encoding = blob_http_headers.blob_content_encoding
        blob_content_language = None
        if blob_http_headers is not None:
            blob_content_language = blob_http_headers.blob_content_language
        blob_content_md5 = None
        if blob_http_headers is not None:
            blob_content_md5 = blob_http_headers.blob_content_md5
        blob_cache_control = None
        if blob_http_headers is not None:
            blob_cache_control = blob_http_headers.blob_cache_control
        blob_content_disposition = None
        if blob_http_headers is not None:
            blob_content_disposition = blob_http_headers.blob_content_disposition
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

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Length'] = self._serialize.header("content_length", content_length, 'long')
        if metadata is not None:
            header_parameters['x-ms-meta'] = self._serialize.header("metadata", metadata, 'str')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        header_parameters['x-ms-blob-type'] = self._serialize.header("self.x_ms_blob_type", self.x_ms_blob_type, 'str')
        if blob_content_type is not None:
            header_parameters['x-ms-blob-content-type'] = self._serialize.header("blob_content_type", blob_content_type, 'str')
        if blob_content_encoding is not None:
            header_parameters['x-ms-blob-content-encoding'] = self._serialize.header("blob_content_encoding", blob_content_encoding, 'str')
        if blob_content_language is not None:
            header_parameters['x-ms-blob-content-language'] = self._serialize.header("blob_content_language", blob_content_language, 'str')
        if blob_content_md5 is not None:
            header_parameters['x-ms-blob-content-md5'] = self._serialize.header("blob_content_md5", blob_content_md5, 'bytearray')
        if blob_cache_control is not None:
            header_parameters['x-ms-blob-cache-control'] = self._serialize.header("blob_cache_control", blob_cache_control, 'str')
        if blob_content_disposition is not None:
            header_parameters['x-ms-blob-content-disposition'] = self._serialize.header("blob_content_disposition", blob_content_disposition, 'str')
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
            raise models.StorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'ETag': self._deserialize('str', response.headers.get('ETag')),
                'Last-Modified': self._deserialize('rfc-1123', response.headers.get('Last-Modified')),
                'Content-MD5': self._deserialize('bytearray', response.headers.get('Content-MD5')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
                'x-ms-request-server-encrypted': self._deserialize('bool', response.headers.get('x-ms-request-server-encrypted')),
                'x-ms-error-code': self._deserialize('str', response.headers.get('x-ms-error-code')),
            }
            return cls(response, None, response_headers)
    create.metadata = {'url': '/{containerName}/{blob}'}

    def append_block(self, body, content_length, timeout=None, transactional_content_md5=None, request_id=None, lease_access_conditions=None, append_position_access_conditions=None, modified_access_conditions=None, cls=None, **kwargs):
        """The Append Block operation commits a new block of data to the end of an
        existing append blob. The Append Block operation is permitted only if
        the blob was created with x-ms-blob-type set to AppendBlob. Append
        Block is supported only on version 2015-02-21 version or later.

        :param body: Initial data
        :type body: Generator
        :param content_length: The length of the request.
        :type content_length: long
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param transactional_content_md5: Specify the transactional md5 for
         the body, to be validated by the service.
        :type transactional_content_md5: bytearray
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions: ~blob.models.LeaseAccessConditions
        :param append_position_access_conditions: Additional parameters for
         the operation
        :type append_position_access_conditions:
         ~blob.models.AppendPositionAccessConditions
        :param modified_access_conditions: Additional parameters for the
         operation
        :type modified_access_conditions:
         ~blob.models.ModifiedAccessConditions
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises:
         :class:`StorageErrorException<blob.models.StorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id
        max_size = None
        if append_position_access_conditions is not None:
            max_size = append_position_access_conditions.max_size
        append_position = None
        if append_position_access_conditions is not None:
            append_position = append_position_access_conditions.append_position
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
        url = self.append_block.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        query_parameters['comp'] = self._serialize.query("self.comp", self.comp, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/octet-stream'
        header_parameters['Content-Length'] = self._serialize.header("content_length", content_length, 'long')
        if transactional_content_md5 is not None:
            header_parameters['Content-MD5'] = self._serialize.header("transactional_content_md5", transactional_content_md5, 'bytearray')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')
        if max_size is not None:
            header_parameters['x-ms-blob-condition-maxsize'] = self._serialize.header("max_size", max_size, 'long')
        if append_position is not None:
            header_parameters['x-ms-blob-condition-appendpos'] = self._serialize.header("append_position", append_position, 'long')
        if if_modified_since is not None:
            header_parameters['If-Modified-Since'] = self._serialize.header("if_modified_since", if_modified_since, 'rfc-1123')
        if if_unmodified_since is not None:
            header_parameters['If-Unmodified-Since'] = self._serialize.header("if_unmodified_since", if_unmodified_since, 'rfc-1123')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')

        # Construct body

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, stream_content=body)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.StorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'ETag': self._deserialize('str', response.headers.get('ETag')),
                'Last-Modified': self._deserialize('rfc-1123', response.headers.get('Last-Modified')),
                'Content-MD5': self._deserialize('bytearray', response.headers.get('Content-MD5')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
                'x-ms-blob-append-offset': self._deserialize('str', response.headers.get('x-ms-blob-append-offset')),
                'x-ms-blob-committed-block-count': self._deserialize('int', response.headers.get('x-ms-blob-committed-block-count')),
                'x-ms-error-code': self._deserialize('str', response.headers.get('x-ms-error-code')),
            }
            return cls(response, None, response_headers)
    append_block.metadata = {'url': '/{containerName}/{blob}'}
