#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------

import logging
import sys
import os
import pytest
import json
import base64
import datetime as dt

from devtools_testutils import AzureMgmtTestCase
from msrest.serialization import UTC
from azure.core.pipeline import (
    PipelineRequest,
    PipelineContext
)
from azure.core.pipeline.transport import HttpRequest
from azure.eventgrid import CloudEvent
from azure.eventgrid._policies import CloudEventDistributedTracingPolicy
from _mocks import (
    cloud_storage_dict
)

_content_type = "application/cloudevents-batch+json; charset=utf-8"
_traceparent_value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
_tracestate_value = "rojo=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01,congo=lZWRzIHRoNhcm5hbCBwbGVhc3VyZS4"


class EventGridSerializationTests(AzureMgmtTestCase):

    def test_cloud_event_policy_copies(self):
        policy = CloudEventDistributedTracingPolicy()

        body = json.dumps([cloud_storage_dict])
        universal_request = HttpRequest('POST', 'http://127.0.0.1/', data=body)
        universal_request.headers['content-type'] = _content_type
        universal_request.headers['traceparent'] = _traceparent_value
        universal_request.headers['tracestate'] = _tracestate_value

        request = PipelineRequest(universal_request, PipelineContext(None))

        resp = policy.on_request(request)

        body = json.loads(request.http_request.body)
    
        for item in body:
            assert 'traceparent' in item
            assert 'tracestate' in item

    def test_cloud_event_policy_no_copy_if_trace_exists(self):
        policy = CloudEventDistributedTracingPolicy()

        cloud_storage_dict.update({'traceparent': 'exists'})
        body = json.dumps([cloud_storage_dict])
        universal_request = HttpRequest('POST', 'http://127.0.0.1/', data=body)
        universal_request.headers['content-type'] = _content_type
        universal_request.headers['traceparent'] = _traceparent_value
        universal_request.headers['tracestate'] = _tracestate_value

        request = PipelineRequest(universal_request, PipelineContext(None))

        resp = policy.on_request(request)

        body = json.loads(request.http_request.body)
    
        for item in body:
            assert 'traceparent' in item
            assert 'tracestate' in item 
            assert item['traceparent'] == 'exists'
