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
import sys

from azure.core.pipeline.transport import (
    HttpRequest,
    AioHttpTransport,
    AioHttpTransportResponse,
    AsyncHttpTransport,
    AsyncioRequestsTransport,
    TrioRequestsTransport)

import json
import aiohttp
import trio

import pytest
from unittest import mock
from azure.core.pipeline import Pipeline


@pytest.mark.asyncio
async def test_basic_aiohttp():

    request = HttpRequest("GET", "https://www.bing.com/")
    async with AioHttpTransport() as sender:
        response = await sender.send(request)
        assert response.body() is not None

    assert sender.session is None
    assert isinstance(response.status_code, int)

@pytest.mark.asyncio
async def test_aiohttp_auto_headers():

    request = HttpRequest("POST", "https://www.bing.com/")
    async with AioHttpTransport() as sender:
        response = await sender.send(request)
        auto_headers = response.internal_response.request_info.headers
        assert 'Content-Type' not in auto_headers

@pytest.mark.asyncio
async def test_basic_async_requests():

    request = HttpRequest("GET", "https://www.bing.com/")
    async with AsyncioRequestsTransport() as sender:
        response = await sender.send(request)
        assert response.body() is not None

    assert isinstance(response.status_code, int)

@pytest.mark.asyncio
async def test_conf_async_requests():

    request = HttpRequest("GET", "https://www.bing.com/")
    async with AsyncioRequestsTransport() as sender:
        response = await sender.send(request)
        assert response.body() is not None

    assert isinstance(response.status_code, int)

def test_conf_async_trio_requests():

    async def do():
        request = HttpRequest("GET", "https://www.bing.com/")
        async with TrioRequestsTransport() as sender:
            return await sender.send(request)
            assert response.body() is not None

    response = trio.run(do)
    assert isinstance(response.status_code, int)


def _create_aiohttp_response(body_bytes, headers=None):
    class MockAiohttpClientResponse(aiohttp.ClientResponse):
        def __init__(self, body_bytes, headers=None):
            self._body = body_bytes
            self._headers = headers
            self._cache = {}

    req_response = MockAiohttpClientResponse(body_bytes, headers)

    response = AioHttpTransportResponse(
        None, # Don't need a request here
        req_response
    )
    response._body = body_bytes

    return response


@pytest.mark.asyncio
async def test_aiohttp_response_text():

    for encoding in ["utf-8", "utf-8-sig", None]:

        res = _create_aiohttp_response(
            b'\xef\xbb\xbf56',
            {'Content-Type': 'text/plain'}
        )
        assert res.text(encoding) == '56', "Encoding {} didn't work".format(encoding)

def test_aiohttp_response_json():
    res = _create_aiohttp_response(b'{"key": "value"}', {'Content-Type': 'application/json'})
    assert res.json() == {"key": "value"}
    assert json.dumps(res.json())

def test_aiohttp_response_json_error():
    res = _create_aiohttp_response(b'this is not json serializable', {'Content-Type': 'application/json'})
    with pytest.raises(json.decoder.JSONDecodeError):
        res.json()

def test_requests_response_json_stream():
    class MockTransport(AioHttpTransport):
        def send(self, request, **kwargs):
            return _create_aiohttp_response(b'{"key": "value"}', {'Content-Type': 'application/json'})

    pipeline = Pipeline(MockTransport())
    pipeline_response = pipeline.run(HttpRequest('GET', 'http://127.0.0.1/'), stream=True)
    res = pipeline_response.http_response
    assert isinstance(res, AioHttpTransportResponse)
    assert res.json() == {"key": "value"}
    assert json.dumps(res.json())