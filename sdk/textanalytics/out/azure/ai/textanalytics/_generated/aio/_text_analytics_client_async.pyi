# Stubs for azure.ai.textanalytics._generated.aio._text_analytics_client_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ._configuration_async import TextAnalyticsClientConfiguration
from .operations_async import TextAnalyticsClientOperationsMixin
from typing import Any

class TextAnalyticsClient(TextAnalyticsClientOperationsMixin):
    api_version: str = ...
    def __init__(self, credentials: Any, endpoint: Any, **kwargs: Any) -> None: ...
    async def close(self) -> None: ...
    async def __aenter__(self): ...
    async def __aexit__(self, *exc_details: Any) -> None: ...
