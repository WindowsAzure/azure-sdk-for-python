# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

import asyncio
import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    # pylint:disable=ungrouped-imports
    from typing import Any, Callable, Union

from azure.core.polling import AsyncPollingMethod
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError

logger = logging.getLogger(__name__)

class DeleteResourcePollerAsync(AsyncPollingMethod):
    def __init__(self, interval=5):
        self._command = None
        self._deleted_resource = None
        self._polling_interval = interval
        self._status = "deleting"

    async def _update_status(self) -> None:
        try:
            await self._command()
            self._status = "deleted"
        except ResourceNotFoundError:
            self._status = "deleting"
        except HttpResponseError as e:
            if e.status_code != 403:
                raise

    def initialize(self, client: "Any", initial_response: str, _: "Callable") -> None:
        self._command = client
        self._deleted_resource = initial_response

    async def run(self) -> None:
        try:
            while not self.finished():
                await self._update_status()
                await asyncio.sleep(self._polling_interval)
        except Exception as e:
            logger.warning(str(e))
            raise

    def finished(self) -> bool:
        return not self._deleted_resource.recovery_id or self._status == "deleted"

    def resource(self) -> "Any":
        return self._deleted_resource

    def status(self) -> str:
        return self._status
