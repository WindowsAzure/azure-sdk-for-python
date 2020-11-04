# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
# pylint: disable=import-error
# pylint: disable=no-member
# pylint: disable=no-name-in-module
import os
import requests
from opentelemetry import trace
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchExportSpanProcessor

from opentelemetry.exporter.azuremonitor import AzureMonitorSpanExporter

trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)
RequestsInstrumentor().instrument()
span_processor = BatchExportSpanProcessor(
    AzureMonitorSpanExporter(
        connection_string = os.environ["AZURE_MONITOR_CONNECTION_STRING"]
    )
)
trace.get_tracer_provider().add_span_processor(span_processor)

response = requests.get(url="http://127.0.0.1:8080/")

input("Press any key to exit...")
