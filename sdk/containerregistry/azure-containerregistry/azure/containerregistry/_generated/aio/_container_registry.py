# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.4.0, generator: @autorest/python@5.6.4)
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from copy import deepcopy
from typing import Any

from azure.core import AsyncPipelineClient
from azure.core.rest import AsyncHttpResponse, HttpRequest
from msrest import Deserializer, Serializer

from ._configuration import ContainerRegistryConfiguration
from .operations import ContainerRegistryOperations
from .operations import ContainerRegistryBlobOperations
from .operations import AuthenticationOperations
from .. import models


class ContainerRegistry(object):
    """Metadata API definition for the Azure Container Registry runtime.

    :ivar container_registry: ContainerRegistryOperations operations
    :vartype container_registry: container_registry.aio.operations.ContainerRegistryOperations
    :ivar container_registry_blob: ContainerRegistryBlobOperations operations
    :vartype container_registry_blob: container_registry.aio.operations.ContainerRegistryBlobOperations
    :ivar authentication: AuthenticationOperations operations
    :vartype authentication: container_registry.aio.operations.AuthenticationOperations
    :param url: Registry login URL.
    :type url: str
    """

    def __init__(
        self,
        url: str,
        **kwargs: Any
    ) -> None:
        base_url = '{url}'
        self._config = ContainerRegistryConfiguration(url, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._deserialize = Deserializer(client_models)

        self.container_registry = ContainerRegistryOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.container_registry_blob = ContainerRegistryBlobOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.authentication = AuthenticationOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False

    async def _send_request(self, http_request: HttpRequest, **kwargs: Any) -> AsyncHttpResponse:
        """Runs the network request through the client's chained policies.

        We have helper methods to create requests specific to this service in `container_registry.rest`.
        Use these helper methods to create the request you pass to this method. See our example below:

        >>> from container_registry.rest import build_containerregistry_check_docker_v2_support_request
        >>> request = build_containerregistry_check_docker_v2_support_request()
        <HttpRequest [GET], url: '/v2/'>
        >>> response = await client.send_request(request)
        <AsyncHttpResponse: 200 OK>

        For more information on this code flow, see https://aka.ms/azsdk/python/llcwiki

        For advanced cases, you can also create your own :class:`~azure.core.rest.HttpRequest`
        and pass it in.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.rest.HttpRequest
        :keyword bool stream_response: Whether the response payload will be streamed. Defaults to False.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.rest.AsyncHttpResponse
        """
        request_copy = deepcopy(http_request)
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
        }
        request_copy.url = self._client.format_url(request_copy.url, **path_format_arguments)
        stream_response = kwargs.pop("stream_response", False)
        pipeline_response = await self._client._pipeline.run(request_copy._internal_request, stream=stream_response, **kwargs)
        return AsyncHttpResponse(
            status_code=pipeline_response.http_response.status_code,
            request=request_copy,
            _internal_response=pipeline_response.http_response
        )

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "ContainerRegistry":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
