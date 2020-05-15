# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import requests
from azure.core.pipeline.transport import (
    HttpRequest,
    HttpResponse,
    HttpTransport,
)
from azure.core.pipeline import Pipeline, PipelineResponse
from azure.core.pipeline.transport._requests_basic import StreamDownloadGenerator
try:
    from unittest import mock
except ImportError:
    import mock

def test_connetion_error_response():
    class MockTransport(HttpTransport):
        def __init__(self):
            self._count = 0

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
        def close(self):
            pass
        def open(self):
            pass

        def send(self, request, **kwargs):
            request = HttpRequest('GET', 'http://127.0.0.1/')
            response = HttpResponse(request, None)
            response.status_code = 200
            return response

        def __next__(self):
            if self._count == 0:
                self._count += 1
                raise requests.exceptions.ConnectionError

    class MockInternalResponse():
        def iter_content(self, block_size):
            return MockTransport()

    http_request = HttpRequest('GET', 'http://127.0.0.1/')
    pipeline = Pipeline(MockTransport())
    http_response = HttpResponse(http_request, None)
    http_response.internal_response = MockInternalResponse()
    stream = StreamDownloadGenerator(pipeline, http_response)
    with mock.patch('time.sleep', return_value=None):
        list(stream)
