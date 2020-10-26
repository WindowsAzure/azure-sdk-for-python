# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
import json
import logging
import typing
from enum import Enum
from urllib.parse import urlparse

from opentelemetry.sdk.metrics.export import MetricsExportResult
from opentelemetry.sdk.trace.export import SpanExportResult
from opentelemetry.sdk.util import ns_to_iso_str
from opentelemetry.trace import Span, SpanKind
from opentelemetry.trace.status import StatusCanonicalCode

from azure.core.exceptions import HttpResponseError
from azure.core.pipeline.policies import ProxyPolicy, RetryPolicy
from opentelemetry.exporter.azuremonitor import utils
from opentelemetry.exporter.azuremonitor._generated import AzureMonitorExporter
from opentelemetry.exporter.azuremonitor._generated.models import TelemetryItem, TrackResponse
from opentelemetry.exporter.azuremonitor.options import ExporterOptions
from opentelemetry.exporter.azuremonitor.storage import LocalFileStorage

logger = logging.getLogger(__name__)


class ExportResult(Enum):
    SUCCESS = 0
    FAILED_RETRYABLE = 1
    FAILED_NOT_RETRYABLE = 2


# pylint: disable=broad-except
class BaseExporter:
    """Azure Monitor base exporter for OpenTelemetry.

    Args:
        options: :doc:`export.options` to allow configuration for the exporter
    """

    def __init__(self, **options):
        self._telemetry_processors = []
        self.options = ExporterOptions(**options)
        retry_policy = RetryPolicy(timeout=self.options.timeout)
        proxy_policy = ProxyPolicy(proxies=self.options.proxies)
        self.client = AzureMonitorExporter(
            self.options.endpoint, proxy_policy=proxy_policy, retry_policy=retry_policy)
        self.storage = LocalFileStorage(
            path=self.options.storage_path,
            max_size=self.options.storage_max_size,
            maintenance_period=self.options.storage_maintenance_period,
            retention_period=self.options.storage_retention_period,
        )

    def add_telemetry_processor(
        self, processor: typing.Callable[..., any]
    ) -> None:
        """Adds telemetry processor to the collection.

        Telemetry processors will be called one by one before telemetry
        item is pushed for sending and in the order they were added.

        Args:
            processor: Processor to add
        """
        self._telemetry_processors.append(processor)

    def clear_telemetry_processors(self) -> None:
        """Removes all telemetry processors"""
        self._telemetry_processors = []

    def _apply_telemetry_processors(
        self, envelopes: typing.List[TelemetryItem]
    ) -> typing.List[TelemetryItem]:
        """Applies all telemetry processors in the order they were added.

        This function will return the list of envelopes to be exported after
        each processor has been run sequentially. Individual processors can
        throw exceptions and fail, but the applying of all telemetry processors
        will proceed (not fast fail). Processors also return True if envelope
        should be included for exporting, False otherwise.

        Args:
            envelopes: The envelopes to apply each processor to.
        """
        filtered_envelopes = []
        for envelope in envelopes:
            accepted = True
            for processor in self._telemetry_processors:
                try:
                    if processor(envelope) is False:
                        accepted = False
                        break
                except Exception as ex:
                    logger.warning("Telemetry processor failed with: %s.", ex)
            if accepted:
                filtered_envelopes.append(envelope)
        return filtered_envelopes

    def _transmit_from_storage(self) -> None:
        for blob in self.storage.gets():
            # give a few more seconds for blob lease operation
            # to reduce the chance of race (for perf consideration)
            if blob.lease(self.options.timeout + 5):
                envelopes = blob.get()
                result = self._transmit(envelopes)
                if result == ExportResult.FAILED_RETRYABLE:
                    blob.lease(1)
                else:
                    blob.delete()

    # pylint: disable=too-many-branches
    # pylint: disable=too-many-nested-blocks
    # pylint: disable=too-many-return-statements
    def _transmit(self, envelopes: typing.List[TelemetryItem]) -> ExportResult:
        """
        Transmit the data envelopes to the ingestion service.

        Returns an ExportResult, this function should never
        throw an exception.
        """
        if len(envelopes) > 0:
            try:
                track_response = self.client.track(envelopes)
                if not track_response.errors:
                    logger.info("Transmission succeeded: Item received: %s. Items accepted: %s",
                                track_response.items_received, track_response.items_accepted)
                    return ExportResult.SUCCESS
                else:
                    resend_envelopes = []
                    for error in track_response.errors:
                        if self._is_retryable_code(error.statusCode):
                            resend_envelopes.append(
                                envelopes[error.index]
                            )
                        else:
                            logger.error(
                                "Data drop %s: %s %s.",
                                error.statusCode,
                                error.message,
                                envelopes[error.index],
                            )
                    if resend_envelopes:
                        self.storage.put(resend_envelopes)

            except HttpResponseError as response_error:
                if self._is_retryable_code(response_error.status_code):
                    return ExportResult.FAILED_RETRYABLE
                else:
                    return ExportResult.FAILED_NOT_RETRYABLE
            except Exception as ex:
                logger.warning(
                    "Retrying due to transient client side error %s.", ex
                )
                # client side error (retryable)
                return ExportResult.FAILED_RETRYABLE
            return ExportResult.FAILED_NOT_RETRYABLE
        # No spans to export
        return ExportResult.SUCCESS

    def _is_retryable_code(self, response_code: int) -> bool:
        """
        Determine if response is retryable
        """
        if response_code in (
            408,  # Timeout
            429,  # Throttle, too Many Requests
            439,  # Quota, too Many Requests over extended time
            500,  # Internal Server Error
            503,  # Service Unavailable
        ):
            return True
        else:
            return False


def get_trace_export_result(result: ExportResult) -> SpanExportResult:
    if result == ExportResult.SUCCESS:
        return SpanExportResult.SUCCESS
    if result in (
        ExportResult.FAILED_RETRYABLE,
        ExportResult.FAILED_NOT_RETRYABLE,
    ):
        return SpanExportResult.FAILURE
    return None


def get_metrics_export_result(result: ExportResult) -> MetricsExportResult:
    if result == ExportResult.SUCCESS:
        return MetricsExportResult.SUCCESS
    if result in (
        ExportResult.FAILED_RETRYABLE,
        ExportResult.FAILED_NOT_RETRYABLE,
    ):
        return MetricsExportResult.FAILURE
    return None
