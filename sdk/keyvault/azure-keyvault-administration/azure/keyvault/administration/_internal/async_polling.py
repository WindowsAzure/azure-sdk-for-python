# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import base64

from azure.core.exceptions import HttpResponseError
from azure.core.polling.async_base_polling import AsyncLROBasePolling
from azure.core.polling.base_polling import BadResponse, BadStatus, OperationFailed

from .helpers import _failed, _get_retry_after, _raise_if_bad_http_status_and_method


class KeyVaultAsyncBackupClientPollingMethod(AsyncLROBasePolling):
    def initialize(self, client, initial_response, deserialization_callback):
        """Set the initial status of this LRO.

        :param initial_response: The initial pipeline response of the poller, or a URL continuation token
        :raises: HttpResponseError if initial status is incorrect LRO state
        """
        if isinstance(initial_response, str):
            self._client = client
            self._deserialization_callback = deserialization_callback
            self._operation = self._lro_algorithms[0]
            self._operation._async_url = initial_response  # pylint: disable=protected-access
            self._status = "InProgress"  # assume the operation is ongoing for now, so the actual status gets polled

        else:
            super().initialize(client, initial_response, deserialization_callback)

    def get_continuation_token(self):
        # type() -> str
        return base64.b64encode(self._operation.get_polling_url().encode()).decode("ascii")

    @classmethod
    def from_continuation_token(cls, continuation_token, **kwargs):
        """continuation_token is expected to be the URL of a pending operation"""
        # type(str, Any) -> Tuple
        try:
            client = kwargs["client"]
        except KeyError:
            raise ValueError("Need kwarg 'client' to be recreated from continuation_token")

        try:
            deserialization_callback = kwargs["deserialization_callback"]
        except KeyError:
            raise ValueError("Need kwarg 'deserialization_callback' to be recreated from continuation_token")

        continuation_url = base64.b64decode(continuation_token.encode()).decode("ascii")
        return client, continuation_url, deserialization_callback

    async def run(self):  # pylint:disable=invalid-overridden-method
        try:
            await self._poll()

        except BadStatus as err:
            self._status = "Failed"
            raise HttpResponseError(response=self._pipeline_response.http_response, error=err)

        except BadResponse as err:
            self._status = "Failed"
            raise HttpResponseError(response=self._pipeline_response.http_response, message=str(err), error=err)

        except OperationFailed as err:
            raise HttpResponseError(response=self._pipeline_response.http_response, error=err)

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

        if _failed(self.status()):
            raise OperationFailed("Operation failed or canceled")

        final_get_url = self._operation.get_final_get_url(self._pipeline_response)
        if final_get_url:
            self._pipeline_response = await self.request_status(final_get_url)
            _raise_if_bad_http_status_and_method(self._pipeline_response.http_response)

    def resource(self):
        try:
            return super().resource()
        except AttributeError:
            return None

    async def _delay(self):  # pylint:disable=invalid-overridden-method
        """Check for a 'retry-after' header to set timeout,
        otherwise use configured timeout.
        """
        delay = self._extract_delay()
        await self._sleep(delay)

    def _extract_delay(self):
        if self._pipeline_response is None:
            return 0
        delay = _get_retry_after(self._pipeline_response)
        if delay:
            return delay
        return self._timeout

    def _get_request_id(self):
        return self._pipeline_response.http_response.request.headers["x-ms-client-request-id"]

    async def request_status(self, status_link):
        """Do a simple GET to this status link.

        This method re-inject 'x-ms-client-request-id'.

        :rtype: azure.core.pipeline.PipelineResponse
        """
        try:
            if self._path_format_arguments:
                status_link = self._client.format_url(status_link, **self._path_format_arguments)
            # Re-inject 'x-ms-client-request-id' while polling
            if "request_id" not in self._operation_config:
                self._operation_config["request_id"] = self._get_request_id()
        except AttributeError:
            pass
        request = self._client.get(status_link)
        return await self._client._pipeline.run(  # pylint: disable=protected-access
            request, stream=False, **self._operation_config
        )
