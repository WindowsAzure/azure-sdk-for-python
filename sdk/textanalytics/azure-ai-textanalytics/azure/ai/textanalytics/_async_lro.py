# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

from azure.core.polling.base_polling import OperationFailed, BadStatus
from azure.core.polling.async_base_polling import AsyncLROBasePolling
from azure.core.polling import AsyncLROPoller


_FINISHED = frozenset(["succeeded", "cancelled", "failed", "partiallysucceeded"])
_FAILED = frozenset(["failed"])
_SUCCEEDED = frozenset(["succeeded", "partiallysucceeded"])


class TextAnalyticsAsyncLROPollingMethod(AsyncLROBasePolling):

    def finished(self):
        """Is this polling finished?
        :rtype: bool
        """
        return TextAnalyticsAsyncLROPollingMethod._finished(self.status())

    @staticmethod
    def _finished(status):
        if hasattr(status, "value"):
            status = status.value
        return str(status).lower() in _FINISHED

    @staticmethod
    def _failed(status):
        if hasattr(status, "value"):
            status = status.value
        return str(status).lower() in _FAILED

    @staticmethod
    def _raise_if_bad_http_status_and_method(response):
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

    async def _poll(self):  # pylint:disable=invalid-overridden-method
        """Poll status of operation so long as operation is incomplete and
        we have an endpoint to query.

        :param callable update_cmd: The function to call to retrieve the
         latest status of the long running operation.
        :raises: OperationFailed if operation status 'Failed' or 'Canceled'.
        :raises: BadStatus if response status invalid.
        :raises: BadResponse if response invalid.
        """
        while not self.finished():
            await self._delay()
            await self.update_status()

        if TextAnalyticsAsyncLROPollingMethod._failed(self.status()):
            raise OperationFailed("Operation failed or canceled")

        final_get_url = self._operation.get_final_get_url(self._pipeline_response)
        if final_get_url:
            self._pipeline_response = await self.request_status(final_get_url)
            TextAnalyticsAsyncLROPollingMethod._raise_if_bad_http_status_and_method(
                self._pipeline_response.http_response
            )

class AsyncAnalyzeBatchActionsLROPollingMethod(TextAnalyticsAsyncLROPollingMethod):

    @property
    def _current_body(self):
        from ._generated.v3_1_preview_3.models import JobMetadata
        return JobMetadata.deserialize(self._pipeline_response)

    @property
    def created_on(self):
        if not self._current_body:
            return None
        return self._current_body.created_date_time

    @property
    def display_name(self):
        if not self._current_body:
            return None
        return self._current_body.display_name

    @property
    def expires_on(self):
        if not self._current_body:
            return None
        return self._current_body.expiration_date_time

    @property
    def actions_failed_count(self):
        if not self._current_body:
            return None
        return self._current_body.additional_properties['tasks']['failed']

    @property
    def actions_in_progress_count(self):
        if not self._current_body:
            return None
        return self._current_body.additional_properties['tasks']['inProgress']

    @property
    def actions_succeeded_count(self):
        if not self._current_body:
            return None
        return self._current_body.additional_properties['tasks']["completed"]

    @property
    def last_modified_on(self):
        if not self._current_body:
            return None
        return self._current_body.last_update_date_time

    @property
    def total_actions_count(self):
        if not self._current_body:
            return None
        return self._current_body.additional_properties['tasks']["total"]

    @property
    def id(self):
        if not self._current_body:
            return None
        return self._current_body.job_id

class AsyncAnalyzeBatchActionsLROPoller(AsyncLROPoller):

    @property
    def created_on(self):
        return self._polling_method.created_on

    @property
    def display_name(self):
        return self._polling_method.display_name

    @property
    def expires_on(self):
        return self._polling_method.expires_on

    @property
    def actions_failed_count(self):
        return self._polling_method.actions_failed_count

    @property
    def actions_in_progress_count(self):
        return self._polling_method.actions_in_progress_count

    @property
    def actions_succeeded_count(self):
        return self._polling_method.actions_succeeded_count

    @property
    def last_modified_on(self):
        return self._polling_method.last_modified_on
    @property
    def total_actions_count(self):
        return self._polling_method.total_actions_count

    @property
    def id(self):
        return self._polling_method.id
