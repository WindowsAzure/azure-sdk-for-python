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

from ._configuration import EventHubManagementClientConfiguration
from .operations import Operations
from .operations import NamespacesOperations
from .operations import EventHubsOperations
from .operations import ConsumerGroupsOperations
from . import models


class EventHubManagementClient(object):
    """Azure Event Hubs client.

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.eventhub.v2015_08_01.operations.Operations
    :ivar namespaces: NamespacesOperations operations
    :vartype namespaces: azure.mgmt.eventhub.v2015_08_01.operations.NamespacesOperations
    :ivar event_hubs: EventHubsOperations operations
    :vartype event_hubs: azure.mgmt.eventhub.v2015_08_01.operations.EventHubsOperations
    :ivar consumer_groups: ConsumerGroupsOperations operations
    :vartype consumer_groups: azure.mgmt.eventhub.v2015_08_01.operations.ConsumerGroupsOperations
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
        self._config = EventHubManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.namespaces = NamespacesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.event_hubs = EventHubsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.consumer_groups = ConsumerGroupsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> EventHubManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
