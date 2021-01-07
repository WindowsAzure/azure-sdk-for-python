# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, TYPE_CHECKING

from azure.core import AsyncPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import AttestationClientConfiguration
from .operations import PolicyOperations
from .operations import PolicyCertificatesOperations
from .operations import AttestationOperations
from .operations import SigningCertificatesOperations
from .operations import MetadataConfigurationOperations
from .. import models


class AttestationClient(object):
    """Describes the interface for the per-tenant enclave service.

    :ivar policy: PolicyOperations operations
    :vartype policy: azure.security.attestation.aio.operations.PolicyOperations
    :ivar policy_certificates: PolicyCertificatesOperations operations
    :vartype policy_certificates: azure.security.attestation.aio.operations.PolicyCertificatesOperations
    :ivar attestation: AttestationOperations operations
    :vartype attestation: azure.security.attestation.aio.operations.AttestationOperations
    :ivar signing_certificates: SigningCertificatesOperations operations
    :vartype signing_certificates: azure.security.attestation.aio.operations.SigningCertificatesOperations
    :ivar metadata_configuration: MetadataConfigurationOperations operations
    :vartype metadata_configuration: azure.security.attestation.aio.operations.MetadataConfigurationOperations
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
        self._config = AttestationClientConfiguration(credential, instance_url, **kwargs)
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

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "AttestationClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
