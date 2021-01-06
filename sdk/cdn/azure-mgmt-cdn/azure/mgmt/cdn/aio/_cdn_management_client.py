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

from ._configuration import CdnManagementClientConfiguration
from .operations import ProfilesOperations
from .operations import EndpointsOperations
from .operations import OriginsOperations
from .operations import OriginGroupsOperations
from .operations import CustomDomainsOperations
from .operations import CdnManagementClientOperationsMixin
from .operations import ResourceUsageOperations
from .operations import Operations
from .operations import EdgeNodesOperations
from .operations import PoliciesOperations
from .operations import ManagedRuleSetsOperations
from .. import models


class CdnManagementClient(CdnManagementClientOperationsMixin):
    """Cdn Management Client.

    :ivar profiles: ProfilesOperations operations
    :vartype profiles: azure.mgmt.cdn.aio.operations.ProfilesOperations
    :ivar endpoints: EndpointsOperations operations
    :vartype endpoints: azure.mgmt.cdn.aio.operations.EndpointsOperations
    :ivar origins: OriginsOperations operations
    :vartype origins: azure.mgmt.cdn.aio.operations.OriginsOperations
    :ivar origin_groups: OriginGroupsOperations operations
    :vartype origin_groups: azure.mgmt.cdn.aio.operations.OriginGroupsOperations
    :ivar custom_domains: CustomDomainsOperations operations
    :vartype custom_domains: azure.mgmt.cdn.aio.operations.CustomDomainsOperations
    :ivar resource_usage: ResourceUsageOperations operations
    :vartype resource_usage: azure.mgmt.cdn.aio.operations.ResourceUsageOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.cdn.aio.operations.Operations
    :ivar edge_nodes: EdgeNodesOperations operations
    :vartype edge_nodes: azure.mgmt.cdn.aio.operations.EdgeNodesOperations
    :ivar policies: PoliciesOperations operations
    :vartype policies: azure.mgmt.cdn.aio.operations.PoliciesOperations
    :ivar managed_rule_sets: ManagedRuleSetsOperations operations
    :vartype managed_rule_sets: azure.mgmt.cdn.aio.operations.ManagedRuleSetsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Azure Subscription ID.
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
        self._config = CdnManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.profiles = ProfilesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.endpoints = EndpointsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.origins = OriginsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.origin_groups = OriginGroupsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.custom_domains = CustomDomainsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.resource_usage = ResourceUsageOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.edge_nodes = EdgeNodesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.policies = PoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.managed_rule_sets = ManagedRuleSetsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "CdnManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
