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

from ._configuration import AzureMediaServicesConfiguration
from .operations import AccountFiltersOperations
from .operations import Operations
from .operations import MediaservicesOperations
from .operations import PrivateLinkResourcesOperations
from .operations import PrivateEndpointConnectionsOperations
from .operations import LocationsOperations
from .operations import AssetsOperations
from .operations import AssetFiltersOperations
from .operations import ContentKeyPoliciesOperations
from .operations import TransformsOperations
from .operations import JobsOperations
from .operations import StreamingPoliciesOperations
from .operations import StreamingLocatorsOperations
from .operations import LiveEventsOperations
from .operations import LiveOutputsOperations
from .operations import StreamingEndpointsOperations
from .. import models


class AzureMediaServices(object):
    """This Swagger was generated by the API Framework.

    :ivar account_filters: AccountFiltersOperations operations
    :vartype account_filters: azure.mgmt.media.aio.operations.AccountFiltersOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.media.aio.operations.Operations
    :ivar mediaservices: MediaservicesOperations operations
    :vartype mediaservices: azure.mgmt.media.aio.operations.MediaservicesOperations
    :ivar private_link_resources: PrivateLinkResourcesOperations operations
    :vartype private_link_resources: azure.mgmt.media.aio.operations.PrivateLinkResourcesOperations
    :ivar private_endpoint_connections: PrivateEndpointConnectionsOperations operations
    :vartype private_endpoint_connections: azure.mgmt.media.aio.operations.PrivateEndpointConnectionsOperations
    :ivar locations: LocationsOperations operations
    :vartype locations: azure.mgmt.media.aio.operations.LocationsOperations
    :ivar assets: AssetsOperations operations
    :vartype assets: azure.mgmt.media.aio.operations.AssetsOperations
    :ivar asset_filters: AssetFiltersOperations operations
    :vartype asset_filters: azure.mgmt.media.aio.operations.AssetFiltersOperations
    :ivar content_key_policies: ContentKeyPoliciesOperations operations
    :vartype content_key_policies: azure.mgmt.media.aio.operations.ContentKeyPoliciesOperations
    :ivar transforms: TransformsOperations operations
    :vartype transforms: azure.mgmt.media.aio.operations.TransformsOperations
    :ivar jobs: JobsOperations operations
    :vartype jobs: azure.mgmt.media.aio.operations.JobsOperations
    :ivar streaming_policies: StreamingPoliciesOperations operations
    :vartype streaming_policies: azure.mgmt.media.aio.operations.StreamingPoliciesOperations
    :ivar streaming_locators: StreamingLocatorsOperations operations
    :vartype streaming_locators: azure.mgmt.media.aio.operations.StreamingLocatorsOperations
    :ivar live_events: LiveEventsOperations operations
    :vartype live_events: azure.mgmt.media.aio.operations.LiveEventsOperations
    :ivar live_outputs: LiveOutputsOperations operations
    :vartype live_outputs: azure.mgmt.media.aio.operations.LiveOutputsOperations
    :ivar streaming_endpoints: StreamingEndpointsOperations operations
    :vartype streaming_endpoints: azure.mgmt.media.aio.operations.StreamingEndpointsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: The unique identifier for a Microsoft Azure subscription.
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
        self._config = AzureMediaServicesConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.account_filters = AccountFiltersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.mediaservices = MediaservicesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_link_resources = PrivateLinkResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.locations = LocationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.assets = AssetsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.asset_filters = AssetFiltersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.content_key_policies = ContentKeyPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.transforms = TransformsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.jobs = JobsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.streaming_policies = StreamingPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.streaming_locators = StreamingLocatorsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.live_events = LiveEventsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.live_outputs = LiveOutputsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.streaming_endpoints = StreamingEndpointsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "AzureMediaServices":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
