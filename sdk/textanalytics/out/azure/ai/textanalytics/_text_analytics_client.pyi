# Stubs for azure.ai.textanalytics._text_analytics_client (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ._base_client import TextAnalyticsClientBase
from ._credential import TextAnalyticsApiKeyCredential
from ._generated.models import TextAnalyticsErrorException
from ._models import AnalyzeSentimentResult, DetectLanguageInput, DetectLanguageResult, DocumentError, ExtractKeyPhrasesResult, RecognizeEntitiesResult, RecognizeLinkedEntitiesResult, RecognizePiiEntitiesResult, TextDocumentInput
from ._request_handlers import _validate_batch_input
from ._response_handlers import entities_result, key_phrases_result, language_result, linked_entities_result, pii_entities_result, process_batch_error, sentiment_result
from azure.core.credentials import TokenCredential
from typing import Any, Dict, List, Union

class TextAnalyticsClient(TextAnalyticsClientBase):
    def __init__(self, endpoint: str, credential: Union[TextAnalyticsApiKeyCredential, TokenCredential], **kwargs: Any) -> None: ...
    def detect_language(self, inputs: Union[List[str], List[DetectLanguageInput], List[Dict[str, str]]], **kwargs: Any) -> List[Union[DetectLanguageResult, DocumentError]]: ...
    def recognize_entities(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], **kwargs: Any) -> List[Union[RecognizeEntitiesResult, DocumentError]]: ...
    def recognize_pii_entities(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], **kwargs: Any) -> List[Union[RecognizePiiEntitiesResult, DocumentError]]: ...
    def recognize_linked_entities(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], **kwargs: Any) -> List[Union[RecognizeLinkedEntitiesResult, DocumentError]]: ...
    def extract_key_phrases(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], **kwargs: Any) -> List[Union[ExtractKeyPhrasesResult, DocumentError]]: ...
    def analyze_sentiment(self, inputs: Union[List[str], List[TextDocumentInput], List[Dict[str, str]]], **kwargs: Any) -> List[Union[AnalyzeSentimentResult, DocumentError]]: ...
