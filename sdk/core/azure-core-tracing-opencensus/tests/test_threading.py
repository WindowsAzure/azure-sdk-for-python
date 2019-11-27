# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import threading

from opencensus.trace.tracer import Tracer
from opencensus.trace.samplers import AlwaysOnSampler

from azure.core.tracing.ext.opencensus_span import OpenCensusSpan


def test_get_span_from_thread():

    result = []
    def get_span_from_thread(output):
        current_span = OpenCensusSpan.get_current_span()
        output.append(current_span)

    tracer = Tracer(sampler=AlwaysOnSampler())
    with tracer.span(name="YijunEventHubTestSend") as span:

        thread = threading.Thread(
            target=get_span_from_thread,
            args=(result,)
        )
        thread.start()
        thread.join()

        assert span is result[0]