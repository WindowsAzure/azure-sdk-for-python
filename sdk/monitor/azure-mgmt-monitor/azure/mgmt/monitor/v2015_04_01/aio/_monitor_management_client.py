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

from ._configuration import MonitorManagementClientConfiguration
from .operations import ActivityLogsOperations
from .operations import AutoscaleSettingsOperations
from .operations import EventCategoriesOperations
from .operations import Operations
from .operations import TenantActivityLogsOperations
from .. import models


class MonitorManagementClient(object):
    """Monitor Management Client.

    :ivar activity_logs: ActivityLogsOperations operations
    :vartype activity_logs: $(python-base-namespace).v2015_04_01.aio.operations.ActivityLogsOperations
    :ivar autoscale_settings: AutoscaleSettingsOperations operations
    :vartype autoscale_settings: $(python-base-namespace).v2015_04_01.aio.operations.AutoscaleSettingsOperations
    :ivar event_categories: EventCategoriesOperations operations
    :vartype event_categories: $(python-base-namespace).v2015_04_01.aio.operations.EventCategoriesOperations
    :ivar operations: Operations operations
    :vartype operations: $(python-base-namespace).v2015_04_01.aio.operations.Operations
    :ivar tenant_activity_logs: TenantActivityLogsOperations operations
    :vartype tenant_activity_logs: $(python-base-namespace).v2015_04_01.aio.operations.TenantActivityLogsOperations
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
        self._config = MonitorManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.activity_logs = ActivityLogsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.autoscale_settings = AutoscaleSettingsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.event_categories = EventCategoriesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.tenant_activity_logs = TenantActivityLogsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "MonitorManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
