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
from typing import TYPE_CHECKING

from azure.core.configuration import Configuration
from azure.core.pipeline import policies

from ._version import VERSION

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

class SearchClientConfiguration(Configuration):
    """Configuration for SearchClient.

    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param endpoint: The endpoint URL of the search service.
    :type endpoint: str
    :param index_name: The name of the index.
    :type index_name: str
    """

    def __init__(
        self,
        endpoint,  # type: str
        index_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        if endpoint is None:
            raise ValueError("Parameter 'endpoint' must not be None.")
        if index_name is None:
            raise ValueError("Parameter 'index_name' must not be None.")
        super(SearchClientConfiguration, self).__init__(**kwargs)

        self.endpoint = endpoint
        self.index_name = index_name
        kwargs.setdefault('sdk_moniker', 'azure-search-documents/{}'.format(VERSION))
        self._configure(**kwargs)

    def _configure(
        self,
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        self.user_agent_policy = kwargs.get('user_agent_policy') or policies.UserAgentPolicy(**kwargs)
        self.headers_policy = kwargs.get('headers_policy') or policies.HeadersPolicy(**kwargs)
        self.proxy_policy = kwargs.get('proxy_policy') or policies.ProxyPolicy(**kwargs)
        self.logging_policy = kwargs.get('logging_policy') or policies.NetworkTraceLoggingPolicy(**kwargs)
        self.http_logging_policy = kwargs.get('http_logging_policy') or policies.HttpLoggingPolicy(**kwargs)
        self.retry_policy = kwargs.get('retry_policy') or policies.RetryPolicy(**kwargs)
        self.custom_hook_policy = kwargs.get('custom_hook_policy') or policies.CustomHookPolicy(**kwargs)
        self.redirect_policy = kwargs.get('redirect_policy') or policies.RedirectPolicy(**kwargs)
        self.authentication_policy = kwargs.get('authentication_policy')
