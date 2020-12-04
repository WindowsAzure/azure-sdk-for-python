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

from ._configuration_async import AzureFileStorageConfiguration
from azure.core.exceptions import map_error
from .operations_async import ServiceOperations
from .operations_async import ShareOperations
from .operations_async import DirectoryOperations
from .operations_async import FileOperations
from .. import models


class AzureFileStorage(object):
    """AzureFileStorage


    :ivar service: Service operations
    :vartype service: azure.storage.fileshare.aio.operations_async.ServiceOperations
    :ivar share: Share operations
    :vartype share: azure.storage.fileshare.aio.operations_async.ShareOperations
    :ivar directory: Directory operations
    :vartype directory: azure.storage.fileshare.aio.operations_async.DirectoryOperations
    :ivar file: File operations
    :vartype file: azure.storage.fileshare.aio.operations_async.FileOperations

    :param version: Specifies the version of the operation to use for this
     request.
    :type version: str
    :param url: The URL of the service account, share, directory or file that
     is the target of the desired operation.
    :type url: str
    """

    def __init__(
            self, version, url, **kwargs):

        base_url = '{url}'
        self._config = AzureFileStorageConfiguration(version, url, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2020-04-08'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.service = ServiceOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.share = ShareOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.directory = DirectoryOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.file = FileOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self):
        await self._client.close()
    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    async def __aexit__(self, *exc_details):
        await self._client.__aexit__(*exc_details)
