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
from typing import Any, Callable, AsyncIterator, Optional

import aiohttp
import logging

from azure.core.exceptions import (
    ServiceRequestError,
    ServiceResponseError,
    ConnectError,
    ReadTimeoutError,
    raise_with_traceback
)
from .base import HttpRequest
from .base_async import (
    AsyncHttpTransport,
    AsyncHttpResponse,
    _ResponseStopIteration,
    _iterate_response_content)

# Matching requests, because why not?
CONTENT_CHUNK_SIZE = 10 * 1024
_LOGGER = logging.getLogger(__name__)


class AioHttpTransport(AsyncHttpTransport):
    """AioHttp HTTP sender implementation.
    """

    def __init__(self, configuration=None, *, loop=None):
        self._loop = loop
        self.session = None
        self.config = configuration

    async def __aenter__(self):
        self.config.connection.keep_alive = True
        self.session = aiohttp.ClientSession(loop=self._loop)
        await self.session.__aenter__()
        return self

    async def __aexit__(self, *exc_details):  # pylint: disable=arguments-differ
        await self.session.__aexit__(*exc_details)
        self.session = None
        self.config.connection.keep_alive = False

    def _build_ssl_confg(self, **config):
        verify = config.get('connection_verify', self.config.connection.verify)
        cert = config.get('connection_cert', self.config.connection.cert)
        ssl_ctx = None

        if cert or verify not in (True, False):
            import ssl
            if verify not in (True, False):
                ssl_ctx = ssl.create_default_context(cafile=verify)
            else:
                ssl_ctx = ssl.create_default_context()
            if cert:
                ssl_ctx.load_cert_chain(*cert)
            return ssl_ctx
        return verify

    async def send(self, request: HttpRequest, **config: Any) -> AsyncHttpResponse:
        """Send the request using this HTTP sender.

        Will pre-load the body into memory to be available with a sync method.
        pass stream=True to avoid this behavior.
        """
        if self.config.connection.keep_alive and self.session:
            session = self.session
        else:
            session = aiohttp.ClientSession(loop=self._loop)
        error = None
        response = None
        config['ssl'] = self._build_ssl_confg(**config)
        try:
            stream_response = config.pop("stream", False)
            result = await session.request(
                request.method,
                request.url,
                headers=request.headers,
                data=request.data,
                # files=request.files,  # TODO: What is aiohttp equivalent...?
                timeout=config.get('connection_timeout', self.config.connection.timeout),
                allow_redirects=False,
                **config
            )
            response = AioHttpTransportResponse(request, result, self.config.connection.data_block_size)
            if not stream_response:
                await response.load_body()
        except aiohttp.client_exceptions.ClientConnectorError as err:
            error = ConnectError(err, error=err)
        finally:
            if not self.config.connection.keep_alive and (not response or not stream_response):
                await session.close()

        if error:
            raise error
        return response


class AioHttpStreamDownloadGenerator(AsyncIterator):

    def __init__(self, response: aiohttp.ClientResponse, block_size: int) -> None:
        self.response = response
        self.block_size = block_size
        self.iter_content_func = self.response.content.read(self.block_size)
        self.content_length = int(response.headers.get('Content-Length', 0))

    def __len__(self):
        return self.content_length

    async def __anext__(self):
        try:
            chunk = await self.iter_content_func
            if not chunk:
                self.response.close()
                raise StopAsyncIteration()
            return chunk
        except Exception as err:
            _LOGGER.warning("Unable to stream download: %s", err)
            self.response.close()
            raise

class AioHttpTransportResponse(AsyncHttpResponse):

    def __init__(self, request: HttpRequest, aiohttp_response: aiohttp.ClientResponse, block_size=None) -> None:
        super(AioHttpTransportResponse, self).__init__(request, aiohttp_response, block_size=block_size)
        # https://aiohttp.readthedocs.io/en/stable/client_reference.html#aiohttp.ClientResponse
        self.status_code = aiohttp_response.status
        self.headers = aiohttp_response.headers
        self.reason = aiohttp_response.reason
        self._body = None

    def body(self) -> bytes:
        """Return the whole body as bytes in memory.
        """
        if self._body is None:
            raise ValueError("Body is not available. Call async method load_body, or do your call with stream=False.")
        return self._body

    async def load_body(self) -> None:
        """Load in memory the body, so it could be accessible from sync methods."""
        self._body = await self.internal_response.read()

    def stream_download(self) -> AsyncIterator[bytes]:
        """Generator for streaming request body data.
        """
        return AioHttpStreamDownloadGenerator(self.internal_response, self.block_size)