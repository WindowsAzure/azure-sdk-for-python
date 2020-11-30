# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any

from azure.core import AsyncPipelineClient
from msrest import Deserializer, Serializer

from ._configuration import AzureCommunicationChatServiceConfiguration
from .operations import AzureCommunicationChatServiceOperationsMixin
from .. import models


class AzureCommunicationChatService(AzureCommunicationChatServiceOperationsMixin):
    """Azure Communication Chat Service.

    :param endpoint: The endpoint of the Azure Communication resource.
    :type endpoint: str
    """

    def __init__(
        self,
        endpoint: str,
        **kwargs: Any
    ) -> None:
        base_url = '{endpoint}'
        self._config = AzureCommunicationChatServiceConfiguration(endpoint, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)


    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "AzureCommunicationChatService":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
