# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------
from azure.core import AsyncPipelineClient
from azure.core.pipeline.policies import (
    ContentDecodePolicy,
    DistributedTracingPolicy,
    RequestIdPolicy,
)
from .policies import AsyncARMAutoResourceProviderRegistrationPolicy, ARMHttpLoggingPolicy


class AsyncARMPipelineClient(AsyncPipelineClient):
    """A pipeline client designed for ARM explicitly.

    :param str base_url: URL for the request.
    :keyword AsyncPipeline pipeline: If omitted, a Pipeline object is created and returned.
    :keyword list[HTTPPolicy] policies: If omitted, the standard policies of the configuration object is used.
    :keyword HttpTransport transport: If omitted, RequestsTransport is used for synchronous transport.
    """

    def __init__(self, base_url, **kwargs):
        if "policies" not in kwargs:
            if "config" not in kwargs:
                raise ValueError(
                    "Current implementation requires to pass 'config' if you don't pass 'policies'"
                )
            per_call_policies = kwargs.get('per_call_policies', [])
            per_call_policies.append(AsyncARMAutoResourceProviderRegistrationPolicy())
            kwargs["per_call_policies"] = per_call_policies
            config = kwargs.get('config')
            if not config.http_logging_policy:
                config.http_logging_policy = kwargs.get('http_logging_policy', ARMHttpLoggingPolicy(**kwargs))
            kwargs["config"] = config
        super(AsyncARMPipelineClient, self).__init__(base_url, **kwargs)
