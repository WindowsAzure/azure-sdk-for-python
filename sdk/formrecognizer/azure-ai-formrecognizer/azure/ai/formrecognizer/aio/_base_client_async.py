# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

from azure.core.configuration import Configuration
from azure.core.pipeline import AsyncPipeline
from azure.core.pipeline.policies import (
    UserAgentPolicy,
    HeadersPolicy,
    RequestIdPolicy,
    ProxyPolicy,
    NetworkTraceLoggingPolicy,
    AsyncRetryPolicy,
    AsyncRedirectPolicy,
    AsyncBearerTokenCredentialPolicy,
    DistributedTracingPolicy,
    HttpLoggingPolicy,
    ContentDecodePolicy,
    CustomHookPolicy
)
from .._policies import CognitiveServicesCredentialPolicy
from .._user_agent import USER_AGENT


class AsyncFormRecognizerClientBase(object):
    def __init__(self, credential, **kwargs):
        self._pipeline = self._create_pipeline(credential, **kwargs)

    def _create_pipeline(self, credential, **kwargs):
        credential_policy = None
        if credential is None:
            raise ValueError("Parameter 'credential' must not be None.")
        if hasattr(credential, "get_token"):
            credential_policy = AsyncBearerTokenCredentialPolicy(
                credential, "https://cognitiveservices.azure.com/.default"
            )
        elif hasattr(credential, "api_key"):
            credential_policy = CognitiveServicesCredentialPolicy(credential)
        elif credential is not None:
            raise TypeError("Unsupported credential: {}. Use an instance of FormRecognizerApiKeyCredential "
                            "or a token credential from azure.identity".format(type(credential)))

        config = self._create_configuration(**kwargs)
        config.transport = kwargs.get("transport")  # type: ignore
        if not config.transport:
            try:
                from azure.core.pipeline.transport import AioHttpTransport
            except ImportError:
                raise ImportError("Unable to create async transport. Please check aiohttp is installed.")
            config.transport = AioHttpTransport(**kwargs)

        policies = [
            config.headers_policy,
            config.user_agent_policy,
            RequestIdPolicy(**kwargs),
            config.proxy_policy,
            config.redirect_policy,
            config.retry_policy,
            credential_policy,
            ContentDecodePolicy(**kwargs),
            config.logging_policy,
            config.custom_hook_policy,
            DistributedTracingPolicy(**kwargs),
            HttpLoggingPolicy(**kwargs),
        ]
        return AsyncPipeline(config.transport, policies=policies)

    def _create_configuration(self, **kwargs):  # pylint: disable=no-self-use
        config = Configuration(**kwargs)
        config.user_agent_policy = kwargs.get("user_agent_policy") or \
            UserAgentPolicy(base_user_agent=USER_AGENT, **kwargs)
        config.headers_policy = kwargs.get("headers_policy") or HeadersPolicy(**kwargs)
        config.proxy_policy = kwargs.get("proxy_policy") or ProxyPolicy(**kwargs)
        config.logging_policy = kwargs.get("logging_policy") or NetworkTraceLoggingPolicy(**kwargs)
        config.retry_policy = kwargs.get("retry_policy") or AsyncRetryPolicy(**kwargs)
        config.redirect_policy = kwargs.get("redirect_policy") or AsyncRedirectPolicy(**kwargs)
        config.custom_hook_policy = kwargs.get('custom_hook_policy') or CustomHookPolicy(**kwargs)

        return config

    async def __aenter__(self):
        await self._client.__aenter__()  # pylint: disable=no-member
        return self

    async def __aexit__(self, *args):
        await self._client.__aexit__(*args)  # pylint: disable=no-member
