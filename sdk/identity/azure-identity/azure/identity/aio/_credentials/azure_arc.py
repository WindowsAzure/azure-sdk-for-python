# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import functools
import os
from typing import TYPE_CHECKING

from azure.core.pipeline.policies import (
    AsyncHTTPPolicy,
    DistributedTracingPolicy,
    HttpLoggingPolicy,
    UserAgentPolicy,
    NetworkTraceLoggingPolicy,
)

from .._internal.managed_identity_base import AsyncManagedIdentityBase
from .._internal.managed_identity_client import AsyncManagedIdentityClient, _get_configuration
from ..._constants import EnvironmentVariables
from ..._credentials.azure_arc import _get_request, _get_secret_key
from ..._internal.user_agent import USER_AGENT

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any, List, Optional, Union
    from azure.core.configuration import Configuration
    from azure.core.pipeline import PipelineRequest, PipelineResponse
    from azure.core.pipeline.policies import SansIOHTTPPolicy
    from azure.core.pipeline.transport import AsyncHttpTransport

    PolicyType = Union[AsyncHTTPPolicy, SansIOHTTPPolicy]


class AzureArcCredential(AsyncManagedIdentityBase):
    def get_client(self, **kwargs: "Any") -> "Optional[AsyncManagedIdentityClient]":
        url = os.environ.get(EnvironmentVariables.IDENTITY_ENDPOINT)
        imds = os.environ.get(EnvironmentVariables.IMDS_ENDPOINT)
        if url and imds:
            config = _get_configuration()
            return AsyncManagedIdentityClient(
                policies=_get_policies(config), request_factory=functools.partial(_get_request, url), **kwargs
            )
        return None

    def get_unavailable_message(self) -> str:
        return "Service Fabric managed identity configuration not found in environment"


def _get_policies(config: "Configuration", **kwargs: "Any") -> "List[PolicyType]":
    return [
        UserAgentPolicy(base_user_agent=USER_AGENT, **kwargs),
        config.proxy_policy,
        config.retry_policy,
        ArcChallengeAuthPolicy(),
        NetworkTraceLoggingPolicy(**kwargs),
        DistributedTracingPolicy(**kwargs),
        HttpLoggingPolicy(**kwargs),
    ]


class ArcChallengeAuthPolicy(AsyncHTTPPolicy):
    """Policy for handling Azure Arc's challenge authentication"""

    def __init__(self):
        # workaround for https://github.com/Azure/azure-sdk-for-python/issues/5797
        super().__init__()
        self.next = None  # type: Union[AsyncHTTPPolicy, AsyncHttpTransport]

    async def send(self, request: "PipelineRequest") -> "PipelineResponse":
        request.http_request.headers["Metadata"] = "true"
        response = await self.next.send(request)

        if response.http_response.status_code == 401:
            secret_key = _get_secret_key(response)
            request.http_request.headers["Authorization"] = "Basic {}".format(secret_key)
            response = await self.next.send(request)

        return response
