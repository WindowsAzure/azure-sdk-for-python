# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, TYPE_CHECKING

from azure.core import AsyncPipelineClient
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import AzureAttestationRestClientConfiguration
from .operations import PolicyOperations
from .operations import PolicyCertificatesOperations
from .operations import AttestationOperations
from .operations import SigningCertificatesOperations
from .operations import MetadataConfigurationOperations
from .. import models


class AzureAttestationRestClient(object):
    """Describes the interface for the per-tenant enclave service.

    :ivar policy: PolicyOperations operations
    :vartype policy: azure.security.attestation._generated.aio.operations.PolicyOperations
    :ivar policy_certificates: PolicyCertificatesOperations operations
    :vartype policy_certificates: azure.security.attestation._generated.aio.operations.PolicyCertificatesOperations
    :ivar attestation: AttestationOperations operations
    :vartype attestation: azure.security.attestation._generated.aio.operations.AttestationOperations
    :ivar signing_certificates: SigningCertificatesOperations operations
    :vartype signing_certificates: azure.security.attestation._generated.aio.operations.SigningCertificatesOperations
    :ivar metadata_configuration: MetadataConfigurationOperations operations
    :vartype metadata_configuration: azure.security.attestation._generated.aio.operations.MetadataConfigurationOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param instance_url: The attestation instance base URI, for example https://mytenant.attest.azure.net.
    :type instance_url: str
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        instance_url: str,
        **kwargs: Any
    ) -> None:
        base_url = '{instanceUrl}'
        self._config = AzureAttestationRestClientConfiguration(credential, instance_url, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.policy = PolicyOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.policy_certificates = PolicyCertificatesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.attestation = AttestationOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.signing_certificates = SigningCertificatesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.metadata_configuration = MetadataConfigurationOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def _send_request(self, http_request: HttpRequest, **kwargs: Any) -> AsyncHttpResponse:
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.pipeline.transport.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to True.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.pipeline.transport.AsyncHttpResponse
        """
        path_format_arguments = {
            'instanceUrl': self._serialize.url("self._config.instance_url", self._config.instance_url, 'str', skip_quote=True),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = await self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "AzureAttestationRestClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
