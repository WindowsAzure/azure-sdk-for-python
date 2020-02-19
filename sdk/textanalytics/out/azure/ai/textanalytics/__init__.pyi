# Stubs for azure.ai.textanalytics (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ._models import AnalyzeSentimentResult as AnalyzeSentimentResult, DetectLanguageInput as DetectLanguageInput, DetectLanguageResult as DetectLanguageResult, DetectedLanguage as DetectedLanguage, DocumentError as DocumentError, ExtractKeyPhrasesResult as ExtractKeyPhrasesResult, InnerError as InnerError, LinkedEntity as LinkedEntity, LinkedEntityMatch as LinkedEntityMatch, NamedEntity as NamedEntity, RecognizeEntitiesResult as RecognizeEntitiesResult, RecognizeLinkedEntitiesResult as RecognizeLinkedEntitiesResult, RecognizePiiEntitiesResult as RecognizePiiEntitiesResult, SentenceSentiment as SentenceSentiment, SentimentConfidenceScorePerLabel as SentimentConfidenceScorePerLabel, TextAnalyticsError as TextAnalyticsError, TextDocumentBatchStatistics as TextDocumentBatchStatistics, TextDocumentInput as TextDocumentInput, TextDocumentStatistics as TextDocumentStatistics
from ._text_analytics_client import TextAnalyticsClient as TextAnalyticsClient
from typing import Any, Optional

def single_detect_language(endpoint: str, credential: str, input_text: str, country_hint: Optional[str]=..., **kwargs: Any) -> DetectLanguageResult: ...
def single_recognize_entities(endpoint: str, credential: str, input_text: str, language: Optional[str]=..., **kwargs: Any) -> RecognizeEntitiesResult: ...
def single_recognize_pii_entities(endpoint: str, credential: str, input_text: str, language: Optional[str]=..., **kwargs: Any) -> RecognizePiiEntitiesResult: ...
def single_recognize_linked_entities(endpoint: str, credential: str, input_text: str, language: Optional[str]=..., **kwargs: Any) -> RecognizeLinkedEntitiesResult: ...
def single_extract_key_phrases(endpoint: str, credential: str, input_text: str, language: Optional[str]=..., **kwargs: Any) -> ExtractKeyPhrasesResult: ...
def single_analyze_sentiment(endpoint: str, credential: str, input_text: str, language: Optional[str]=..., **kwargs: Any) -> AnalyzeSentimentResult: ...
