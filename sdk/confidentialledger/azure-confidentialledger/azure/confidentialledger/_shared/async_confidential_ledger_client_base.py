# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

from typing import Any, TYPE_CHECKING, Union

from azure.core.pipeline.policies import (
    AsyncBearerTokenCredentialPolicy,
    HttpLoggingPolicy,
)
from azure.core.pipeline.transport import AioHttpTransport

from .._generated_ledger.v0_1_preview.aio import (
    ConfidentialLedgerClient as _ConfidentialLedgerClient,
)
from .confidential_ledger_client_base import DEFAULT_VERSION
from .credential import ConfidentialLedgerCertificateCredential

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential


class AsyncConfidentialLedgerClientBase(object):
    def __init__(
        self,
        *,
        endpoint: str,
        credential: Union[ConfidentialLedgerCertificateCredential, "TokenCredential"],
        ledger_certificate_path: str,
        **kwargs: Any
    ) -> None:

        client = kwargs.get("generated_client")
        if client:
            # caller provided a configured client -> nothing left to initialize
            self._client = client
            return

        if not endpoint:
            raise ValueError("Expected endpoint to be a non-empty string")

        if not credential:
            raise ValueError("Expected credential to not be None")

        if not isinstance(ledger_certificate_path, str):
            raise TypeError("ledger_certificate_path must be a string")

        if ledger_certificate_path == "":
            raise ValueError(
                "If not None, ledger_certificate_path must be a non-empty string"
            )

        endpoint = endpoint.strip(" /")
        try:
            if not endpoint.startswith("https://"):
                self._endpoint = "https://" + endpoint
            else:
                self._endpoint = endpoint
        except AttributeError as e:
            raise ValueError("Confidential Ledger URL must be a string.") from e

        self.api_version = kwargs.pop("api_version", DEFAULT_VERSION)

        pipeline = kwargs.pop("pipeline", None)
        transport = kwargs.pop("transport", None)
        if transport is None:
            # Customize the transport layer to use client certificate authentication and validate
            # a self-signed TLS certificate.
            if isinstance(credential, ConfidentialLedgerCertificateCredential):
                # The async version of the client seems to expect a sequence of filenames.
                # azure/core/pipeline/transport/_aiohttp.py:163
                # > ssl_ctx.load_cert_chain(*cert)
                kwargs["connection_cert"] = (credential.certificate_path,)

            kwargs["connection_verify"] = ledger_certificate_path
            transport = AioHttpTransport(**kwargs)

        http_logging_policy = HttpLoggingPolicy(**kwargs)
        http_logging_policy.allowed_header_names.update(
            {
                "x-ms-keyvault-network-info",
                "x-ms-keyvault-region",
                "x-ms-keyvault-service-version",
            }
        )

        if not isinstance(credential, ConfidentialLedgerCertificateCredential):
            kwargs["authentication_policy"] = kwargs.pop(
                "authentication_policy",
                AsyncBearerTokenCredentialPolicy(
                    credential,
                    "https://confidential-ledger.azure.com/.default",
                    **kwargs
                ),
            )

        try:
            self._client = _ConfidentialLedgerClient(
                self._endpoint,
                api_version=self.api_version,
                pipeline=pipeline,
                transport=transport,
                http_logging_policy=http_logging_policy,
                **kwargs
            )
        except NotImplementedError as e:
            raise NotImplementedError(
                "This package doesn't support API version '{}'. ".format(
                    self.api_version
                )
                + "Supported versions: 0.1-preview"
            ) from e

    @property
    def endpoint(self) -> str:
        """The URL this client is connected to."""
        return self._endpoint

    async def __aenter__(self) -> "AsyncConfidentialLedgerClientBase":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.__aexit__(*args)

    async def close(self) -> None:
        """Close sockets opened by the client.

        Calling this method is unnecessary when using the client as a context manager.
        """
        await self._client.close()
