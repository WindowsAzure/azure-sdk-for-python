# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import AzureBotServiceConfiguration
from .operations import BotsOperations
from .operations import ChannelsOperations
from .operations import DirectLineOperations
from .operations import Operations
from .operations import BotConnectionOperations
from .. import models


class AzureBotService(object):
    """Azure Bot Service is a platform for creating smart conversational agents.

    :ivar bots: BotsOperations operations
    :vartype bots: azure.mgmt.botservice.aio.operations.BotsOperations
    :ivar channels: ChannelsOperations operations
    :vartype channels: azure.mgmt.botservice.aio.operations.ChannelsOperations
    :ivar direct_line: DirectLineOperations operations
    :vartype direct_line: azure.mgmt.botservice.aio.operations.DirectLineOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.botservice.aio.operations.Operations
    :ivar bot_connection: BotConnectionOperations operations
    :vartype bot_connection: azure.mgmt.botservice.aio.operations.BotConnectionOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Azure Subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = AzureBotServiceConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.bots = BotsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.channels = ChannelsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.direct_line = DirectLineOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.bot_connection = BotConnectionOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "AzureBotService":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
