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

from ._configuration import ContainerServiceClientConfiguration
from .operations import Operations
from .operations import ManagedClustersOperations
from .operations import MaintenanceConfigurationsOperations
from .operations import AgentPoolsOperations
from .operations import PrivateEndpointConnectionsOperations
from .operations import PrivateLinkResourcesOperations
from .operations import ResolvePrivateLinkServiceIdOperations
from .. import models


class ContainerServiceClient(object):
    """The Container Service Client.

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.containerservice.v2021_02_01.aio.operations.Operations
    :ivar managed_clusters: ManagedClustersOperations operations
    :vartype managed_clusters: azure.mgmt.containerservice.v2021_02_01.aio.operations.ManagedClustersOperations
    :ivar maintenance_configurations: MaintenanceConfigurationsOperations operations
    :vartype maintenance_configurations: azure.mgmt.containerservice.v2021_02_01.aio.operations.MaintenanceConfigurationsOperations
    :ivar agent_pools: AgentPoolsOperations operations
    :vartype agent_pools: azure.mgmt.containerservice.v2021_02_01.aio.operations.AgentPoolsOperations
    :ivar private_endpoint_connections: PrivateEndpointConnectionsOperations operations
    :vartype private_endpoint_connections: azure.mgmt.containerservice.v2021_02_01.aio.operations.PrivateEndpointConnectionsOperations
    :ivar private_link_resources: PrivateLinkResourcesOperations operations
    :vartype private_link_resources: azure.mgmt.containerservice.v2021_02_01.aio.operations.PrivateLinkResourcesOperations
    :ivar resolve_private_link_service_id: ResolvePrivateLinkServiceIdOperations operations
    :vartype resolve_private_link_service_id: azure.mgmt.containerservice.v2021_02_01.aio.operations.ResolvePrivateLinkServiceIdOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Subscription credentials which uniquely identify Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
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
        self._config = ContainerServiceClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.managed_clusters = ManagedClustersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.maintenance_configurations = MaintenanceConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.agent_pools = AgentPoolsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_link_resources = PrivateLinkResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.resolve_private_link_service_id = ResolvePrivateLinkServiceIdOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "ContainerServiceClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
