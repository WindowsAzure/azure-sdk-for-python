# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import os
from typing import Any, Iterable, Mapping, Optional, Union

from azure.core import Configuration
from azure.core.pipeline.policies import ContentDecodePolicy, HeadersPolicy, NetworkTraceLoggingPolicy, AsyncRetryPolicy

from ._authn_client import AsyncAuthnClient
from .._base import ClientSecretCredentialBase, CertificateCredentialBase
from ..constants import EnvironmentVariables, IMDS_ENDPOINT, OAUTH_ENDPOINT
from ..credentials import TokenCredentialChain
from ..exceptions import AuthenticationError

# pylint:disable=too-few-public-methods


class AsyncClientSecretCredential(ClientSecretCredentialBase):
    def __init__(
        self,
        client_id: str,
        secret: str,
        tenant_id: str,
        config: Optional[Configuration] = None,
        **kwargs: Mapping[str, Any]
    ) -> None:
        super(AsyncClientSecretCredential, self).__init__(client_id, secret, tenant_id, **kwargs)
        self._client = AsyncAuthnClient(OAUTH_ENDPOINT.format(tenant_id), config, **kwargs)

    async def get_token(self, scopes: Iterable[str]) -> str:
        token = self._client.get_cached_token(scopes)
        if not token:
            data = dict(self._form_data, scope=" ".join(scopes))
            token = await self._client.request_token(scopes, form_data=data)
        return token  # type: ignore


class AsyncCertificateCredential(CertificateCredentialBase):
    def __init__(
        self,
        client_id: str,
        tenant_id: str,
        private_key: str,
        thumbprint: str,
        config: Optional[Configuration] = None,
        **kwargs: Mapping[str, Any]
    ) -> None:
        super(AsyncCertificateCredential, self).__init__(client_id, tenant_id, private_key, thumbprint, **kwargs)
        self._client = AsyncAuthnClient(OAUTH_ENDPOINT.format(tenant_id), config, **kwargs)

    async def get_token(self, scopes: Iterable[str]) -> str:
        token = self._client.get_cached_token(scopes)
        if not token:
            data = dict(self._form_data, scope=" ".join(scopes))
            token = await self._client.request_token(scopes, form_data=data)
        return token  # type: ignore


class AsyncEnvironmentCredential:
    def __init__(self, **kwargs: Mapping[str, Any]) -> None:
        self._credential = None  # type: Optional[Union[AsyncCertificateCredential, AsyncClientSecretCredential]]

        if not any(v for v in EnvironmentVariables.CLIENT_SECRET_VARS if os.environ.get(v) is None):
            self._credential = AsyncClientSecretCredential(
                client_id=os.environ[EnvironmentVariables.AZURE_CLIENT_ID],
                secret=os.environ[EnvironmentVariables.AZURE_CLIENT_SECRET],
                tenant_id=os.environ[EnvironmentVariables.AZURE_TENANT_ID],
                **kwargs
            )
        elif not any(v for v in EnvironmentVariables.CERT_VARS if os.environ.get(v) is None):
            try:
                with open(os.environ[EnvironmentVariables.AZURE_PRIVATE_KEY_FILE]) as private_key_file:
                    private_key = private_key_file.read()
            except IOError:
                return

            self._credential = AsyncCertificateCredential(
                client_id=os.environ[EnvironmentVariables.AZURE_CLIENT_ID],
                tenant_id=os.environ[EnvironmentVariables.AZURE_TENANT_ID],
                private_key=private_key,
                thumbprint=os.environ[EnvironmentVariables.AZURE_THUMBPRINT],
                **kwargs
            )

    async def get_token(self, scopes):
        if not self._credential:
            raise AuthenticationError("required environment variables not defined")
        return await self._credential.get_token(scopes)


class AsyncManagedIdentityCredential:
    def __init__(self, config: Optional[Configuration] = None, **kwargs: Mapping[str, Any]) -> None:
        config = config or self.create_config(**kwargs)
        policies = [config.header_policy, ContentDecodePolicy(), config.logging_policy, config.retry_policy]
        self._client = AsyncAuthnClient(IMDS_ENDPOINT, config, policies)

    async def get_token(self, scopes: Iterable[str]) -> str:
        scopes = list(scopes)
        if len(scopes) != 1:
            raise ValueError("Managed identity credential supports one scope per request")
        token = self._client.get_cached_token(scopes)
        if not token:
            resource = scopes[0].rstrip("/.default")
            token = await self._client.request_token(
                scopes, method="GET", params={"api-version": "2018-02-01", "resource": resource}
            )
        return token  # type: ignore

    @staticmethod
    def create_config(**kwargs: Mapping[str, Any]) -> Configuration:
        config = Configuration(**kwargs)
        config.header_policy = HeadersPolicy(base_headers={"Metadata": "true"}, **kwargs)
        config.logging_policy = NetworkTraceLoggingPolicy(**kwargs)
        config.retry_policy = AsyncRetryPolicy(
            retry_on_status_codes=[404, 429] + [x for x in range(500, 600)], **kwargs
        )
        return config


class AsyncTokenCredentialChain(TokenCredentialChain):
    """A sequence of token credentials"""

    @classmethod
    def default(cls):
        return cls([AsyncEnvironmentCredential(), AsyncManagedIdentityCredential()])

    async def get_token(self, scopes: Iterable[str]) -> str:
        """Attempts to get a token from each credential, in order, returning the first token.
           If no token is acquired, raises an exception listing error messages.
        """
        history = []
        for credential in self._credentials:
            try:
                return await credential.get_token(scopes)
            except AuthenticationError as ex:
                history.append((credential, ex.message))
            except Exception as ex:  # pylint: disable=broad-except
                history.append((credential, str(ex)))
        error_message = self._get_error_message(history)
        raise AuthenticationError(error_message)
