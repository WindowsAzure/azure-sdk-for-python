# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

from six.moves.urllib.parse import urlencode
from azure.core.polling.base_polling import LROBasePolling, OperationResourcePolling, OperationFailed, BadStatus


_FINISHED = frozenset(["succeeded", "cancelled", "failed", "partiallysucceeded"])
_FAILED = frozenset(["failed"])
_SUCCEEDED = frozenset(["succeeded", "partiallysucceeded"])


class TextAnalyticsOperationResourcePolling(OperationResourcePolling):
    def __init__(self, operation_location_header="operation-location", show_stats=False):
        super(TextAnalyticsOperationResourcePolling, self).__init__(operation_location_header=operation_location_header)
        self._show_stats = show_stats
        self._query_params = {
            "showStats": show_stats
        }

    def get_polling_url(self):
        if not self._show_stats:
            return super().get_polling_url()

        return super().get_polling_url() + "?" + urlencode(self._query_params)


class TextAnalyticsLROPoller(LROBasePolling):
    def __init__(self,
        timeout=30,
        lro_algorithms=None,
        lro_options=None,
        path_format_arguments=None,
        **operation_config
    ):

        super(TextAnalyticsLROPoller, self).__init__(
            timeout=timeout,
            lro_algorithms=lro_algorithms,
            lro_options=lro_options,
            path_format_arguments=path_format_arguments,
            **operation_config
        )

    def finished(self):
        """Is this polling finished?
        :rtype: bool
        """
        return self._finished(self.status())

    def _finished(self, status):
        print("current status: " + str(status).lower())
        if hasattr(status, "value"):
            status = status.value
        return str(status).lower() in _FINISHED

    def _failed(self, status):
        if hasattr(status, "value"):
            status = status.value
        return str(status).lower() in _FAILED

    def _raise_if_bad_http_status_and_method(self, response):
        # type: (ResponseType) -> None
        """Check response status code is valid.

        Must be 200, 201, 202, or 204.

        :raises: BadStatus if invalid status.
        """
        code = response.status_code
        if code in {200, 201, 202, 204}:
            return
        raise BadStatus(
            "Invalid return status {!r} for {!r} operation".format(
                code, response.request.method
            )
        )

    def _poll(self):
        """Poll status of operation so long as operation is incomplete and
        we have an endpoint to query.

        :param callable update_cmd: The function to call to retrieve the
         latest status of the long running operation.
        :raises: OperationFailed if operation status 'Failed' or 'Canceled'.
        :raises: BadStatus if response status invalid.
        :raises: BadResponse if response invalid.
        """

        while not self.finished():
            self._delay()
            self.update_status()

        if self._failed(self.status()):
            raise OperationFailed("Operation failed or canceled")

        final_get_url = self._operation.get_final_get_url(self._pipeline_response)
        if final_get_url:
            self._pipeline_response = self.request_status(final_get_url)
            self._raise_if_bad_http_status_and_method(self._pipeline_response.http_response)
