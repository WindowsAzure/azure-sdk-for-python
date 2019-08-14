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

from azure.core import AsyncPipelineClient
from msrest import Serializer, Deserializer

from ._configuration_async import AzureBlobStorageConfiguration
from .operations_async import ServiceOperations
from .operations_async import ContainerOperations
from .operations_async import DirectoryOperations
from .operations_async import BlobOperations
from .operations_async import PageBlobOperations
from .operations_async import AppendBlobOperations
from .operations_async import BlockBlobOperations
from .. import models


class AzureBlobStorage(object):
    """AzureBlobStorage


    :ivar service: Service operations
    :vartype service: azure.storage.blob.operations.ServiceOperations
    :ivar container: Container operations
    :vartype container: azure.storage.blob.operations.ContainerOperations
    :ivar directory: Directory operations
    :vartype directory: azure.storage.blob.operations.DirectoryOperations
    :ivar blob: Blob operations
    :vartype blob: azure.storage.blob.operations.BlobOperations
    :ivar page_blob: PageBlob operations
    :vartype page_blob: azure.storage.blob.operations.PageBlobOperations
    :ivar append_blob: AppendBlob operations
    :vartype append_blob: azure.storage.blob.operations.AppendBlobOperations
    :ivar block_blob: BlockBlob operations
    :vartype block_blob: azure.storage.blob.operations.BlockBlobOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param url: The URL of the service account, container, or blob that is the
     targe of the desired operation.
    :type url: str
    :param filter: The filter parameter enables the caller to query blobs
     whose tags match a given expression. The given expression must evaluate to
     true for a blob to be returned in the results.
    :type filter: str
    :param path_rename_mode: Determines the behavior of the rename operation.
     Possible values include: 'legacy', 'posix'
    :type path_rename_mode: str or ~azure.storage.blob.models.PathRenameMode
    """

    def __init__(
            self, credentials, url, filter, path_rename_mode=None, **kwargs):

        base_url = '{url}'
        self._config = AzureBlobStorageConfiguration(credentials, url, filter, path_rename_mode, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-02-02'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.service = ServiceOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.container = ContainerOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.directory = DirectoryOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.blob = BlobOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.page_blob = PageBlobOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.append_blob = AppendBlobOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.block_blob = BlockBlobOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    async def __aexit__(self, *exc_details):
        await self._client.__aexit__(*exc_details)
