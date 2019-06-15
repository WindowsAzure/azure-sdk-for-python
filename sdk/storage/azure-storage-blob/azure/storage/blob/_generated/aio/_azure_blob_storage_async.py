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
from azure.core.exceptions import map_error
from .operations_async import ServiceOperations
from .operations_async import ContainerOperations
from .operations_async import BlobOperations
from .operations_async import PageBlobOperations
from .operations_async import AppendBlobOperations
from .operations_async import BlockBlobOperations
from .. import models


class AzureBlobStorage(object):
    """AzureBlobStorage


    :ivar service: Service operations
    :vartype service: blob.aio.operations_async.ServiceOperations
    :ivar container: Container operations
    :vartype container: blob.aio.operations_async.ContainerOperations
    :ivar blob: Blob operations
    :vartype blob: blob.aio.operations_async.BlobOperations
    :ivar page_blob: PageBlob operations
    :vartype page_blob: blob.aio.operations_async.PageBlobOperations
    :ivar append_blob: AppendBlob operations
    :vartype append_blob: blob.aio.operations_async.AppendBlobOperations
    :ivar block_blob: BlockBlob operations
    :vartype block_blob: blob.aio.operations_async.BlockBlobOperations

    :param url: The URL of the service account, container, or blob that is the
     targe of the desired operation.
    :type url: str
    """

    def __init__(
            self, url, config=None, **kwargs):

        base_url = '{url}'
        self._config = config or AzureBlobStorageConfiguration(url, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-03-28'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.service = ServiceOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.container = ContainerOperations(
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
