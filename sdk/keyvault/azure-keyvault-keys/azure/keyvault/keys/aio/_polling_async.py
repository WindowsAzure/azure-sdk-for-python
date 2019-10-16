# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

import asyncio
import logging
from typing import Any, Callable, Union
from azure.core.polling import AsyncPollingMethod
from azure.core.exceptions import ResourceNotFoundError
from ..models import DeletedKey


logger = logging.getLogger(__name__)


class DeleteKeyPollerAsync(AsyncPollingMethod):
    def __init__(self, interval=5):
        self._command = None
        self._deleted_key = None
        self._polling_interval = interval
        self._status = None

    async def _update_status(self) -> None:
        # type: () -> None
        try:
            self._deleted_key = await self._command()
            self._status = "deleted"
        except ResourceNotFoundError:
            self._deleted_key = None
            self._status = "deleting"

    def initialize(self, client: Any, initial_response: str, _: Callable) -> None:
        self._command = client
        self._status = initial_response

    async def run(self) -> None:
        try:
            while not self.finished():
                await self._update_status()
                await asyncio.sleep(self._polling_interval)
        except Exception as e:
            logger.warning(str(e))
            raise

    def finished(self) -> bool:
        return self._status == "deleted"

    def resource(self) -> DeletedKey:
        return self._deleted_key

    def status(self) -> str:
        return self._status
