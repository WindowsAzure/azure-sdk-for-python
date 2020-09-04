# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AspectConfidenceScoreLabel
    from ._models_py3 import AspectRelation
    from ._models_py3 import DetectedLanguage
    from ._models_py3 import DocumentEntities
    from ._models_py3 import DocumentError
    from ._models_py3 import DocumentKeyPhrases
    from ._models_py3 import DocumentLanguage
    from ._models_py3 import DocumentLinkedEntities
    from ._models_py3 import DocumentSentiment
    from ._models_py3 import DocumentStatistics
    from ._models_py3 import EntitiesResult
    from ._models_py3 import Entity
    from ._models_py3 import EntityLinkingResult
    from ._models_py3 import ErrorResponse
    from ._models_py3 import InnerError
    from ._models_py3 import KeyPhraseResult
    from ._models_py3 import LanguageBatchInput
    from ._models_py3 import LanguageInput
    from ._models_py3 import LanguageResult
    from ._models_py3 import LinkedEntity
    from ._models_py3 import Match
    from ._models_py3 import MultiLanguageBatchInput
    from ._models_py3 import MultiLanguageInput
    from ._models_py3 import RequestStatistics
    from ._models_py3 import SentenceAspect
    from ._models_py3 import SentenceOpinion
    from ._models_py3 import SentenceSentiment
    from ._models_py3 import SentimentConfidenceScorePerLabel
    from ._models_py3 import SentimentResponse
    from ._models_py3 import TextAnalyticsError
    from ._models_py3 import TextAnalyticsWarning
except (SyntaxError, ImportError):
    from ._models import AspectConfidenceScoreLabel  # type: ignore
    from ._models import AspectRelation  # type: ignore
    from ._models import DetectedLanguage  # type: ignore
    from ._models import DocumentEntities  # type: ignore
    from ._models import DocumentError  # type: ignore
    from ._models import DocumentKeyPhrases  # type: ignore
    from ._models import DocumentLanguage  # type: ignore
    from ._models import DocumentLinkedEntities  # type: ignore
    from ._models import DocumentSentiment  # type: ignore
    from ._models import DocumentStatistics  # type: ignore
    from ._models import EntitiesResult  # type: ignore
    from ._models import Entity  # type: ignore
    from ._models import EntityLinkingResult  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import InnerError  # type: ignore
    from ._models import KeyPhraseResult  # type: ignore
    from ._models import LanguageBatchInput  # type: ignore
    from ._models import LanguageInput  # type: ignore
    from ._models import LanguageResult  # type: ignore
    from ._models import LinkedEntity  # type: ignore
    from ._models import Match  # type: ignore
    from ._models import MultiLanguageBatchInput  # type: ignore
    from ._models import MultiLanguageInput  # type: ignore
    from ._models import RequestStatistics  # type: ignore
    from ._models import SentenceAspect  # type: ignore
    from ._models import SentenceOpinion  # type: ignore
    from ._models import SentenceSentiment  # type: ignore
    from ._models import SentimentConfidenceScorePerLabel  # type: ignore
    from ._models import SentimentResponse  # type: ignore
    from ._models import TextAnalyticsError  # type: ignore
    from ._models import TextAnalyticsWarning  # type: ignore

from ._text_analytics_client_enums import (
    AspectRelationType,
    DocumentSentimentValue,
    ErrorCodeValue,
    InnerErrorCodeValue,
    SentenceSentimentValue,
    StringIndexType,
    TokenSentimentValue,
    WarningCodeValue,
)

__all__ = [
    'AspectConfidenceScoreLabel',
    'AspectRelation',
    'DetectedLanguage',
    'DocumentEntities',
    'DocumentError',
    'DocumentKeyPhrases',
    'DocumentLanguage',
    'DocumentLinkedEntities',
    'DocumentSentiment',
    'DocumentStatistics',
    'EntitiesResult',
    'Entity',
    'EntityLinkingResult',
    'ErrorResponse',
    'InnerError',
    'KeyPhraseResult',
    'LanguageBatchInput',
    'LanguageInput',
    'LanguageResult',
    'LinkedEntity',
    'Match',
    'MultiLanguageBatchInput',
    'MultiLanguageInput',
    'RequestStatistics',
    'SentenceAspect',
    'SentenceOpinion',
    'SentenceSentiment',
    'SentimentConfidenceScorePerLabel',
    'SentimentResponse',
    'TextAnalyticsError',
    'TextAnalyticsWarning',
    'AspectRelationType',
    'DocumentSentimentValue',
    'ErrorCodeValue',
    'InnerErrorCodeValue',
    'SentenceSentimentValue',
    'StringIndexType',
    'TokenSentimentValue',
    'WarningCodeValue',
]
