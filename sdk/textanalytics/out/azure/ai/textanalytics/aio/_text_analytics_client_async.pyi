# Stubs for azure.ai.textanalytics.aio._text_analytics_client_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .._generated.models import TextAnalyticsErrorException
from .._models import AnalyzeSentimentResult, DetectLanguageInput, DetectLanguageResult, DocumentError, ExtractKeyPhrasesResult, RecognizeEntitiesResult, RecognizeLinkedEntitiesResult, RecognizePiiEntitiesResult, TextDocumentInput
from .._request_handlers import _validate_batch_input
from .._response_handlers import entities_result, key_phrases_result, language_result, linked_entities_result, pii_entities_result, process_batch_error, sentiment_result
from ._base_client_async import AsyncTextAnalyticsClientBase
from typing import Any, Dict, List, Optional, Union

class TextAnalyticsClient(AsyncTextAnalyticsClientBase):
    def __init__(self, endpoint: str, credential: Any, **kwargs: Any) -> None: ...
    async def detect_languages(self, inputs: Union[List[str], List[DetectLanguageInput], List[Dict[str, str]]], country_hint: Optional[str]=..., **kwargs: Any) -> List[Union[DetectLanguageResult, DocumentError]]: ...
    async def recognize_entities(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], language: Optional[str]=..., **kwargs: Any) -> List[Union[RecognizeEntitiesResult, DocumentError]]: ...
    async def recognize_pii_entities(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], language: Optional[str]=..., **kwargs: Any) -> List[Union[RecognizePiiEntitiesResult, DocumentError]]: ...
    async def recognize_linked_entities(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], language: Optional[str]=..., **kwargs: Any) -> List[Union[RecognizeLinkedEntitiesResult, DocumentError]]: ...
    async def extract_key_phrases(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], language: Optional[str]=..., **kwargs: Any) -> List[Union[ExtractKeyPhrasesResult, DocumentError]]: ...
    async def analyze_sentiment(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], language: Optional[str]=..., **kwargs: Any) -> List[Union[AnalyzeSentimentResult, DocumentError]]: ...
