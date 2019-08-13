# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

import uuid
from azure.core.exceptions import map_error

from ... import models


class BlockBlobOperations:
    """BlockBlobOperations async operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar x_ms_blob_type: Specifies the type of blob to create: block blob, page blob, or append blob. Constant value: "BlockBlob".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer) -> None:

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.x_ms_blob_type = "BlockBlob"

        self._config = config

    async def upload(self, body, content_length, timeout=None, metadata=None, request_id=None, blob_http_headers=None, lease_access_conditions=None, modified_access_conditions=None, *, cls=None, **kwargs):
        """The Upload Block Blob operation updates the content of an existing
        block blob. Updating an existing block blob overwrites any existing
        metadata on the blob. Partial updates are not supported with Put Blob;
        the content of the existing blob is overwritten with the content of the
        new blob. To perform a partial update of the content of a block blob,
        use the Put Block List operation.

        :param body: Initial data
        :type body: Generator
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
        url = self.upload.metadata['url']
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
        header_parameters['Content-Type'] = 'application/octet-stream'
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
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

        # Construct body

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, stream_content=body)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
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
    upload.metadata = {'url': '/{containerName}/{blob}'}

    async def stage_block(self, block_id, content_length, body, transactional_content_md5=None, timeout=None, request_id=None, lease_access_conditions=None, *, cls=None, **kwargs):
        """The Stage Block operation creates a new block to be committed as part
        of a blob.

        :param block_id: A valid Base64 string value that identifies the
         block. Prior to encoding, the string must be less than or equal to 64
         bytes in size. For a given blob, the length of the value specified for
         the blockid parameter must be the same size for each block.
        :type block_id: str
        :param content_length: The length of the request.
        :type content_length: long
        :param body: Initial data
        :type body: Generator
        :param transactional_content_md5: Specify the transactional md5 for
         the body, to be validated by the service.
        :type transactional_content_md5: bytearray
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions: ~blob.models.LeaseAccessConditions
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

        comp = "block"

        # Construct URL
        url = self.stage_block.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['blockid'] = self._serialize.query("block_id", block_id, 'str')
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        query_parameters['comp'] = self._serialize.query("comp", comp, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/octet-stream'
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        header_parameters['Content-Length'] = self._serialize.header("content_length", content_length, 'long')
        if transactional_content_md5 is not None:
            header_parameters['Content-MD5'] = self._serialize.header("transactional_content_md5", transactional_content_md5, 'bytearray')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')

        # Construct body

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, stream_content=body)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.StorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'Content-MD5': self._deserialize('bytearray', response.headers.get('Content-MD5')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
                'x-ms-request-server-encrypted': self._deserialize('bool', response.headers.get('x-ms-request-server-encrypted')),
                'x-ms-error-code': self._deserialize('str', response.headers.get('x-ms-error-code')),
            }
            return cls(response, None, response_headers)
    stage_block.metadata = {'url': '/{containerName}/{blob}'}

    async def stage_block_from_url(self, block_id, content_length, source_url, source_range=None, source_content_md5=None, timeout=None, request_id=None, lease_access_conditions=None, *, cls=None, **kwargs):
        """The Stage Block operation creates a new block to be committed as part
        of a blob where the contents are read from a URL.

        :param block_id: A valid Base64 string value that identifies the
         block. Prior to encoding, the string must be less than or equal to 64
         bytes in size. For a given blob, the length of the value specified for
         the blockid parameter must be the same size for each block.
        :type block_id: str
        :param content_length: The length of the request.
        :type content_length: long
        :param source_url: Specify a URL to the copy source.
        :type source_url: str
        :param source_range: Bytes of source data in the specified range.
        :type source_range: str
        :param source_content_md5: Specify the md5 calculated for the range of
         bytes that must be read from the copy source.
        :type source_content_md5: bytearray
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions: ~blob.models.LeaseAccessConditions
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

        comp = "block"

        # Construct URL
        url = self.stage_block_from_url.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['blockid'] = self._serialize.query("block_id", block_id, 'str')
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        query_parameters['comp'] = self._serialize.query("comp", comp, 'str')

        # Construct headers
        header_parameters = {}
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        header_parameters['Content-Length'] = self._serialize.header("content_length", content_length, 'long')
        header_parameters['x-ms-copy-source'] = self._serialize.header("source_url", source_url, 'str')
        if source_range is not None:
            header_parameters['x-ms-source-range'] = self._serialize.header("source_range", source_range, 'str')
        if source_content_md5 is not None:
            header_parameters['x-ms-source-content-md5'] = self._serialize.header("source_content_md5", source_content_md5, 'bytearray')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.StorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'Content-MD5': self._deserialize('bytearray', response.headers.get('Content-MD5')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
                'x-ms-request-server-encrypted': self._deserialize('bool', response.headers.get('x-ms-request-server-encrypted')),
                'x-ms-error-code': self._deserialize('str', response.headers.get('x-ms-error-code')),
            }
            return cls(response, None, response_headers)
    stage_block_from_url.metadata = {'url': '/{containerName}/{blob}'}

    async def commit_block_list(self, blocks, timeout=None, metadata=None, request_id=None, blob_http_headers=None, lease_access_conditions=None, modified_access_conditions=None, *, cls=None, **kwargs):
        """The Commit Block List operation writes a blob by specifying the list of
        block IDs that make up the blob. In order to be written as part of a
        blob, a block must have been successfully written to the server in a
        prior Put Block operation. You can call Put Block List to update a blob
        by uploading only those blocks that have changed, then committing the
        new and existing blocks together. You can do this by specifying whether
        to commit a block from the committed block list or from the uncommitted
        block list, or to commit the most recently uploaded version of the
        block, whichever list it may belong to.

        :param blocks:
        :type blocks: ~blob.models.BlockLookupList
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
        blob_cache_control = None
        if blob_http_headers is not None:
            blob_cache_control = blob_http_headers.blob_cache_control
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

        comp = "blocklist"

        # Construct URL
        url = self.commit_block_list.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        query_parameters['comp'] = self._serialize.query("comp", comp, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/xml; charset=utf-8'
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if metadata is not None:
            header_parameters['x-ms-meta'] = self._serialize.header("metadata", metadata, 'str')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if blob_cache_control is not None:
            header_parameters['x-ms-blob-cache-control'] = self._serialize.header("blob_cache_control", blob_cache_control, 'str')
        if blob_content_type is not None:
            header_parameters['x-ms-blob-content-type'] = self._serialize.header("blob_content_type", blob_content_type, 'str')
        if blob_content_encoding is not None:
            header_parameters['x-ms-blob-content-encoding'] = self._serialize.header("blob_content_encoding", blob_content_encoding, 'str')
        if blob_content_language is not None:
            header_parameters['x-ms-blob-content-language'] = self._serialize.header("blob_content_language", blob_content_language, 'str')
        if blob_content_md5 is not None:
            header_parameters['x-ms-blob-content-md5'] = self._serialize.header("blob_content_md5", blob_content_md5, 'bytearray')
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

        # Construct body
        body_content = self._serialize.body(blocks, 'BlockLookupList')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
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
    commit_block_list.metadata = {'url': '/{containerName}/{blob}'}

    async def get_block_list(self, list_type="committed", snapshot=None, timeout=None, request_id=None, lease_access_conditions=None, *, cls=None, **kwargs):
        """The Get Block List operation retrieves the list of blocks that have
        been uploaded as part of a block blob.

        :param list_type: Specifies whether to return the list of committed
         blocks, the list of uncommitted blocks, or both lists together.
         Possible values include: 'committed', 'uncommitted', 'all'
        :type list_type: str or ~blob.models.BlockListType
        :param snapshot: The snapshot parameter is an opaque DateTime value
         that, when present, specifies the blob snapshot to retrieve. For more
         information on working with blob snapshots, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/creating-a-snapshot-of-a-blob">Creating
         a Snapshot of a Blob.</a>
        :type snapshot: str
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions: ~blob.models.LeaseAccessConditions
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: BlockList or the result of cls(response)
        :rtype: ~blob.models.BlockList
        :raises:
         :class:`StorageErrorException<blob.models.StorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id

        comp = "blocklist"

        # Construct URL
        url = self.get_block_list.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if snapshot is not None:
            query_parameters['snapshot'] = self._serialize.query("snapshot", snapshot, 'str')
        query_parameters['blocklisttype'] = self._serialize.query("list_type", list_type, 'BlockListType')
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        query_parameters['comp'] = self._serialize.query("comp", comp, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/xml'
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.StorageErrorException(response, self._deserialize)

        header_dict = {}
        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('BlockList', response)
            header_dict = {
                'Last-Modified': self._deserialize('rfc-1123', response.headers.get('Last-Modified')),
                'ETag': self._deserialize('str', response.headers.get('ETag')),
                'Content-Type': self._deserialize('str', response.headers.get('Content-Type')),
                'x-ms-blob-content-length': self._deserialize('long', response.headers.get('x-ms-blob-content-length')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
                'x-ms-error-code': self._deserialize('str', response.headers.get('x-ms-error-code')),
            }

        if cls:
            return cls(response, deserialized, header_dict)

        return deserialized
    get_block_list.metadata = {'url': '/{containerName}/{blob}'}
