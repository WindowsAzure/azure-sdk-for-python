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
    from azure.core.pipeline.transport import HttpRequest, HttpResponse

from ._configuration import AzureDeploymentManagerConfiguration
from .operations import ServiceTopologiesOperations
from .operations import ServicesOperations
from .operations import ServiceUnitsOperations
from .operations import StepsOperations
from .operations import RolloutsOperations
from .operations import ArtifactSourcesOperations
from .operations import Operations
from . import models


class AzureDeploymentManager(object):
    """REST APIs for orchestrating deployments using the Azure Deployment Manager (ADM). See https://docs.microsoft.com/en-us/azure/azure-resource-manager/deployment-manager-overview for more information.

    :ivar service_topologies: ServiceTopologiesOperations operations
    :vartype service_topologies: azure.mgmt.deploymentmanager.operations.ServiceTopologiesOperations
    :ivar services: ServicesOperations operations
    :vartype services: azure.mgmt.deploymentmanager.operations.ServicesOperations
    :ivar service_units: ServiceUnitsOperations operations
    :vartype service_units: azure.mgmt.deploymentmanager.operations.ServiceUnitsOperations
    :ivar steps: StepsOperations operations
    :vartype steps: azure.mgmt.deploymentmanager.operations.StepsOperations
    :ivar rollouts: RolloutsOperations operations
    :vartype rollouts: azure.mgmt.deploymentmanager.operations.RolloutsOperations
    :ivar artifact_sources: ArtifactSourcesOperations operations
    :vartype artifact_sources: azure.mgmt.deploymentmanager.operations.ArtifactSourcesOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.deploymentmanager.operations.Operations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: Subscription credentials which uniquely identify Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
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
        self._config = AzureDeploymentManagerConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.service_topologies = ServiceTopologiesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.services = ServicesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_units = ServiceUnitsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.steps = StepsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.rollouts = RolloutsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.artifact_sources = ArtifactSourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)

    def _send_request(self, http_request, **kwargs):
        # type: (HttpRequest, Any) -> HttpResponse
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.pipeline.transport.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to True.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.pipeline.transport.HttpResponse
        """
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> AzureDeploymentManager
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
