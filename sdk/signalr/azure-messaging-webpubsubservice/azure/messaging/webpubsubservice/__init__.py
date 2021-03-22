# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

__all__ = ["WebPubSubServiceClient"]

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import Any

import azure.core.credentials as corecredentials
import azure.core.pipeline as corepipeline
import azure.core.pipeline.policies as corepolicies
import azure.core.pipeline.transport as coretransport

# Temporary location for types that eventually graduate to Azure Core
from .core import rest as corerest
from ._policies import JwtCredentialPolicy


class WebPubSubServiceClient(object):
    def __init__(self, endpoint, credentials, **kwargs):
        # type: (str, corecredentials.AzureKeyCredential, Any) -> None
        """Create a new WebPubSubServiceClient instance

        :param endpoint: Endpoint to connect to.
        :type endpoint: ~str
        :param credentials: Credentials to use to connect to endpoint.
        :type credentials: ~azure.core.credentials.AzureKeyCredentials
        :keyword api_version: Api version to use when communicating with the service.
        :type api_version: str
        :keyword user: User to connect as. Optional.
        :type user: ~str
        """
        self.endpoint = endpoint.rstrip("/")
        transport = kwargs.pop("transport", None) or coretransport.RequestsTransport(
            **kwargs
        )
        policies = [
            corepolicies.HeadersPolicy(**kwargs),
            corepolicies.UserAgentPolicy(**kwargs),
            corepolicies.RetryPolicy(**kwargs),
            corepolicies.ProxyPolicy(**kwargs),
            corepolicies.CustomHookPolicy(**kwargs),
            corepolicies.RedirectPolicy(**kwargs),
            JwtCredentialPolicy(credentials, kwargs.get("user", None)),
            corepolicies.NetworkTraceLoggingPolicy(**kwargs),
        ]
        self._pipeline = corepipeline.Pipeline(
            transport,
            policies,
        )

    def _format_url(self, url):
        # type: (str) -> str
        assert self.endpoint[-1] != "/", "My endpoint should not have a trailing slash"
        return "/".join([self.endpoint, url.lstrip("/")])

    def send_request(self, request, **kwargs):
        # type: (corerest.HttpRequest, Any) -> corerest.HttpResponse
        """Runs the network request through the client's chained policies.

        :param request: The network request you want to make. Required.
        :type request: ~corerest.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to False
        :return: The response of your network call.
        :rtype: ~corerest.HttpResponse
        """
        kwargs.setdefault('stream', False)
        request.url = self._format_url(
            request.url
        )  # BUGBUG - should create new request, not mutate the existing one...
        pipeline_response = self._pipeline.run(request._internal_request, **kwargs)
        return corerest.HttpResponse(
            status_code=pipeline_response.http_response.status_code,
            request=request,
            _internal_response=pipeline_response.http_response,
        )
