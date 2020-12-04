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

from ._configuration import MonitorClientConfiguration
from .operations import GuestDiagnosticsSettingsAssociationOperations
from .operations import GuestDiagnosticsSettingsOperations
from .. import models


class MonitorClient(object):
    """Monitor Management Client.

    :ivar guest_diagnostics_settings_association: GuestDiagnosticsSettingsAssociationOperations operations
    :vartype guest_diagnostics_settings_association: $(python-base-namespace).v2018_06_01_preview.aio.operations.GuestDiagnosticsSettingsAssociationOperations
    :ivar guest_diagnostics_settings: GuestDiagnosticsSettingsOperations operations
    :vartype guest_diagnostics_settings: $(python-base-namespace).v2018_06_01_preview.aio.operations.GuestDiagnosticsSettingsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: The Azure subscription Id.
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
        self._config = MonitorClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.guest_diagnostics_settings_association = GuestDiagnosticsSettingsAssociationOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.guest_diagnostics_settings = GuestDiagnosticsSettingsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "MonitorClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
