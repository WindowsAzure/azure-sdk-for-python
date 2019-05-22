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

from ._configuration_async import KeyVaultClientConfiguration
from .operations_async import KeyVaultClientOperationsMixin
from .. import models


class KeyVaultClient(KeyVaultClientOperationsMixin):
    """The key vault client performs cryptographic key operations and vault operations against the Key Vault service.


    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    """

    def __init__(
            self, credentials, config=None, **kwargs):

        base_url = '{vaultBaseUrl}'
        self._config = config or KeyVaultClientConfiguration(credentials, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '7.0'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)


    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    async def __aexit__(self, *exc_details):
        await self._client.__aexit__(*exc_details)
