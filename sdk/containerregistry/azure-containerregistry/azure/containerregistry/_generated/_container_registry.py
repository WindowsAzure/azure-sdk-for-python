# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.2.1, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.core import PipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

    from azure.core.pipeline.transport import HttpRequest, HttpResponse

from ._configuration import ContainerRegistryConfiguration
from .operations import ContainerRegistryOperations
from .operations import ContainerRegistryRepositoryOperations
from .operations import ContainerRegistryBlobOperations
from .operations import AuthenticationOperations
from . import models


class ContainerRegistry(object):
    """Metadata API definition for the Azure Container Registry runtime.

    :ivar container_registry: ContainerRegistryOperations operations
    :vartype container_registry: container_registry.operations.ContainerRegistryOperations
    :ivar container_registry_repository: ContainerRegistryRepositoryOperations operations
    :vartype container_registry_repository: container_registry.operations.ContainerRegistryRepositoryOperations
    :ivar container_registry_blob: ContainerRegistryBlobOperations operations
    :vartype container_registry_blob: container_registry.operations.ContainerRegistryBlobOperations
    :ivar authentication: AuthenticationOperations operations
    :vartype authentication: container_registry.operations.AuthenticationOperations
    :param url: Registry login URL.
    :type url: str
    """

    def __init__(
        self,
        url,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        base_url = '{url}'
        self._config = ContainerRegistryConfiguration(url, **kwargs)
        self._client = PipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.container_registry = ContainerRegistryOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.container_registry_repository = ContainerRegistryRepositoryOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.container_registry_blob = ContainerRegistryBlobOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.authentication = AuthenticationOperations(
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
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> ContainerRegistry
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
