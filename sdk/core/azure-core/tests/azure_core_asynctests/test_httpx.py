#--------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#--------------------------------------------------------------------------
import io

from azure.core.pipeline import (
    Pipeline
)
from azure.core.pipeline.transport import (
    HttpRequest
)
from azure.core.pipeline.policies import (
    UserAgentPolicy,
    RedirectPolicy
)
from azure.core.pipeline.transport._httpx import HttpXTransport

class TestHttpXTransport:

    def test_basic_requests(self):

        request = HttpRequest("GET", "https://bing.com")
        policies = [
            UserAgentPolicy("myusergant"),
            RedirectPolicy()
        ]
        with Pipeline(HttpXTransport(), policies=policies) as pipeline:
            response = pipeline.run(request)

        assert pipeline._transport.client is None
        assert isinstance(response.http_response.status_code, int)

    def test_streaming_requests(self):

        request = HttpRequest("GET", "https://bing.com")
        policies = [
            UserAgentPolicy("myusergant"),
            RedirectPolicy()
        ]
        with Pipeline(HttpXTransport(), policies=policies) as pipeline:
            response = pipeline.run(request, stream=True)
            http_response = response.http_response

            body = b"".join(http_response.stream_download(pipeline))

        assert pipeline._transport.client is None
        assert isinstance(response.http_response.status_code, int)
