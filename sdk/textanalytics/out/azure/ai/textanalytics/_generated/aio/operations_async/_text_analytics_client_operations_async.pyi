# Stubs for azure.ai.textanalytics._generated.aio.operations_async._text_analytics_client_operations_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional

class TextAnalyticsClientOperationsMixin:
    async def entities_recognition_general(self, documents: Any, model_version: Optional[Any] = ..., show_stats: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def entities_recognition_pii(self, documents: Any, model_version: Optional[Any] = ..., show_stats: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def entities_linking(self, documents: Any, model_version: Optional[Any] = ..., show_stats: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def key_phrases(self, documents: Any, model_version: Optional[Any] = ..., show_stats: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def languages(self, documents: Any, model_version: Optional[Any] = ..., show_stats: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def sentiment(self, documents: Any, model_version: Optional[Any] = ..., show_stats: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
