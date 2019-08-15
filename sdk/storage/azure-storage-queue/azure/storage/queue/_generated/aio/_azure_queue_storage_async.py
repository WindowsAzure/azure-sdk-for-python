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

from ._configuration_async import AzureQueueStorageConfiguration
from azure.core.exceptions import map_error
from .operations_async import ServiceOperations
from .operations_async import QueueOperations
from .operations_async import MessagesOperations
from .operations_async import MessageIdOperations
from .. import models


class AzureQueueStorage(object):
    """AzureQueueStorage


    :ivar service: Service operations
    :vartype service: azure.storage.queue.aio.operations_async.ServiceOperations
    :ivar queue: Queue operations
    :vartype queue: azure.storage.queue.aio.operations_async.QueueOperations
    :ivar messages: Messages operations
    :vartype messages: azure.storage.queue.aio.operations_async.MessagesOperations
    :ivar message_id: MessageId operations
    :vartype message_id: azure.storage.queue.aio.operations_async.MessageIdOperations

    :param url: The URL of the service account, queue or message that is the
     targe of the desired operation.
    :type url: str
    """

    def __init__(
            self, url, **kwargs):

        base_url = '{url}'
        self._config = AzureQueueStorageConfiguration(url, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-03-28'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.service = ServiceOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.queue = QueueOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.messages = MessagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.message_id = MessageIdOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    async def __aexit__(self, *exc_details):
        await self._client.__aexit__(*exc_details)
