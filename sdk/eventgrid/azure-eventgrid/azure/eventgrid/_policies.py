# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import json
import logging
from azure.core.pipeline.policies import SansIOHTTPPolicy

_LOGGER = logging.getLogger(__name__)


class CloudEventDistributedTracingPolicy(SansIOHTTPPolicy):
    """CloudEventDistributedTracingPolicy is a policy which adds distributed tracing informatiom
    to a batch of cloud events. It does so by copying the `traceparent` and `tracestate` properties
    from the HTTP request into the individual events as extension properties.
    This will only happen in the case where an event does not have a `traceparent` defined already. This
    allows events to explicitly set a traceparent and tracestate which would be respected during "multi-hop
    transmition".
    See https://github.com/cloudevents/spec/blob/master/extensions/distributed-tracing.md
    for more information on distributed tracing and cloud events.
    """
    def on_request(self, request):
        # type: (PipelineRequest) -> None
        traceparent = request.http_request.headers['traceparent']
        tracestate = request.http_request.headers['tracestate']
        content_type = "application/cloudevents-batch+json; charset=utf-8"

        if (request.http_request.headers['content-type'] == content_type
            and traceparent is not None
            and getattr(request.http_request, 'body') is not None
            ):

            try:
                body = json.loads(request.http_request.body)

                for item in body:
                    if 'traceparent' not in item:
                        item['traceparent'] = traceparent

                    if tracestate:
                        item['tracestate'] = tracestate

                request.http_request.body = json.dumps(body)
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning("Unable to add traceparent: %s", err)
