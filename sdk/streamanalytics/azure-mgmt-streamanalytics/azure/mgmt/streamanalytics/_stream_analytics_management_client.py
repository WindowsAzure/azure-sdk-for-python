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

from ._configuration import StreamAnalyticsManagementClientConfiguration
from .operations import FunctionsOperations
from .operations import InputsOperations
from .operations import OutputsOperations
from .operations import StreamingJobsOperations
from .operations import SubscriptionsOperations
from .operations import TransformationsOperations
from .operations import Operations
from .operations import ClustersOperations
from .operations import PrivateEndpointsOperations
from . import models


class StreamAnalyticsManagementClient(object):
    """Stream Analytics Client.

    :ivar functions: FunctionsOperations operations
    :vartype functions: stream_analytics_management_client.operations.FunctionsOperations
    :ivar inputs: InputsOperations operations
    :vartype inputs: stream_analytics_management_client.operations.InputsOperations
    :ivar outputs: OutputsOperations operations
    :vartype outputs: stream_analytics_management_client.operations.OutputsOperations
    :ivar streaming_jobs: StreamingJobsOperations operations
    :vartype streaming_jobs: stream_analytics_management_client.operations.StreamingJobsOperations
    :ivar subscriptions: SubscriptionsOperations operations
    :vartype subscriptions: stream_analytics_management_client.operations.SubscriptionsOperations
    :ivar transformations: TransformationsOperations operations
    :vartype transformations: stream_analytics_management_client.operations.TransformationsOperations
    :ivar operations: Operations operations
    :vartype operations: stream_analytics_management_client.operations.Operations
    :ivar clusters: ClustersOperations operations
    :vartype clusters: stream_analytics_management_client.operations.ClustersOperations
    :ivar private_endpoints: PrivateEndpointsOperations operations
    :vartype private_endpoints: stream_analytics_management_client.operations.PrivateEndpointsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The ID of the target subscription.
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
        self._config = StreamAnalyticsManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.functions = FunctionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.inputs = InputsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.outputs = OutputsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.streaming_jobs = StreamingJobsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.subscriptions = SubscriptionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.transformations = TransformationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.clusters = ClustersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_endpoints = PrivateEndpointsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> StreamAnalyticsManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
