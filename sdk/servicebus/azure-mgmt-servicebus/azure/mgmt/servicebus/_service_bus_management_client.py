# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.mgmt.core import ARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional

    from azure.core.credentials import TokenCredential

from ._configuration import ServiceBusManagementClientConfiguration
from .operations import NamespacesOperations
from .operations import PrivateEndpointConnectionsOperations
from .operations import PrivateLinkResourcesOperations
from .operations import Operations
from .operations import DisasterRecoveryConfigsOperations
from .operations import QueuesOperations
from .operations import TopicsOperations
from .operations import EventHubsOperations
from .operations import MigrationConfigsOperations
from .operations import PremiumMessagingRegionsOperations
from .operations import RegionsOperations
from .operations import SubscriptionsOperations
from .operations import RulesOperations
from . import models


class ServiceBusManagementClient(object):
    """Azure Service Bus client for managing Namespace, IPFilter Rules, VirtualNetworkRules and Zone Redundant.

    :ivar namespaces: NamespacesOperations operations
    :vartype namespaces: azure.mgmt.servicebus.operations.NamespacesOperations
    :ivar private_endpoint_connections: PrivateEndpointConnectionsOperations operations
    :vartype private_endpoint_connections: azure.mgmt.servicebus.operations.PrivateEndpointConnectionsOperations
    :ivar private_link_resources: PrivateLinkResourcesOperations operations
    :vartype private_link_resources: azure.mgmt.servicebus.operations.PrivateLinkResourcesOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.servicebus.operations.Operations
    :ivar disaster_recovery_configs: DisasterRecoveryConfigsOperations operations
    :vartype disaster_recovery_configs: azure.mgmt.servicebus.operations.DisasterRecoveryConfigsOperations
    :ivar queues: QueuesOperations operations
    :vartype queues: azure.mgmt.servicebus.operations.QueuesOperations
    :ivar topics: TopicsOperations operations
    :vartype topics: azure.mgmt.servicebus.operations.TopicsOperations
    :ivar event_hubs: EventHubsOperations operations
    :vartype event_hubs: azure.mgmt.servicebus.operations.EventHubsOperations
    :ivar migration_configs: MigrationConfigsOperations operations
    :vartype migration_configs: azure.mgmt.servicebus.operations.MigrationConfigsOperations
    :ivar premium_messaging_regions: PremiumMessagingRegionsOperations operations
    :vartype premium_messaging_regions: azure.mgmt.servicebus.operations.PremiumMessagingRegionsOperations
    :ivar regions: RegionsOperations operations
    :vartype regions: azure.mgmt.servicebus.operations.RegionsOperations
    :ivar subscriptions: SubscriptionsOperations operations
    :vartype subscriptions: azure.mgmt.servicebus.operations.SubscriptionsOperations
    :ivar rules: RulesOperations operations
    :vartype rules: azure.mgmt.servicebus.operations.RulesOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: Subscription credentials that uniquely identify a Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        base_url=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = ServiceBusManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.namespaces = NamespacesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_link_resources = PrivateLinkResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.disaster_recovery_configs = DisasterRecoveryConfigsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.queues = QueuesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.topics = TopicsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.event_hubs = EventHubsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.migration_configs = MigrationConfigsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.premium_messaging_regions = PremiumMessagingRegionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.regions = RegionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.subscriptions = SubscriptionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.rules = RulesOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> ServiceBusManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
