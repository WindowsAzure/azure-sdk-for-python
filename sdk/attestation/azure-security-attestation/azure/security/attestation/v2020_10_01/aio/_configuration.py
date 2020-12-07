# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, TYPE_CHECKING

from azure.core.configuration import Configuration
from azure.core.pipeline import policies

from .._version import VERSION

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential


class AttestationClientConfiguration(Configuration):
    """Configuration for AttestationClient.

    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param tenant_base_url: The tenant name, for example https://mytenant.attest.azure.net.
    :type tenant_base_url: str
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        tenant_base_url: str,
        **kwargs: Any
    ) -> None:
        if credential is None:
            raise ValueError("Parameter 'credential' must not be None.")
        if tenant_base_url is None:
            raise ValueError("Parameter 'tenant_base_url' must not be None.")
        super(AttestationClientConfiguration, self).__init__(**kwargs)

        self.credential = credential
        self.tenant_base_url = tenant_base_url
        self.api_version = "2018-09-01-preview"
        self.credential_scopes = kwargs.pop('credential_scopes', ['https://attest.azure.net/.default'])
        kwargs.setdefault('sdk_moniker', 'security-attestation/{}'.format(VERSION))
        self._configure(**kwargs)

    def _configure(
        self,
        **kwargs: Any
    ) -> None:
        self.user_agent_policy = kwargs.get('user_agent_policy') or policies.UserAgentPolicy(**kwargs)
        self.headers_policy = kwargs.get('headers_policy') or policies.HeadersPolicy(**kwargs)
        self.proxy_policy = kwargs.get('proxy_policy') or policies.ProxyPolicy(**kwargs)
        self.logging_policy = kwargs.get('logging_policy') or policies.NetworkTraceLoggingPolicy(**kwargs)
        self.http_logging_policy = kwargs.get('http_logging_policy') or policies.HttpLoggingPolicy(**kwargs)
        self.retry_policy = kwargs.get('retry_policy') or policies.AsyncRetryPolicy(**kwargs)
        self.custom_hook_policy = kwargs.get('custom_hook_policy') or policies.CustomHookPolicy(**kwargs)
        self.redirect_policy = kwargs.get('redirect_policy') or policies.AsyncRedirectPolicy(**kwargs)
        self.authentication_policy = kwargs.get('authentication_policy')
        if self.credential and not self.authentication_policy:
            self.authentication_policy = policies.AsyncBearerTokenCredentialPolicy(self.credential, *self.credential_scopes, **kwargs)
