# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AnalyzeBatchInput
    from ._models_py3 import AnalyzeJobState
    from ._models_py3 import AspectConfidenceScoreLabel
    from ._models_py3 import AspectRelation
    from ._models_py3 import Components15Gvwi3SchemasTasksstatePropertiesTasksPropertiesEntityrecognitiontasksItemsAllof1
    from ._models_py3 import Components15X8E9LSchemasTasksstatePropertiesTasksPropertiesEntityrecognitionpiitasksItemsAllof1
    from ._models_py3 import Components1D9IzucSchemasTasksstatePropertiesTasksPropertiesKeyphraseextractiontasksItemsAllof1
    from ._models_py3 import DetectedLanguage
    from ._models_py3 import DocumentEntities
    from ._models_py3 import DocumentError
    from ._models_py3 import DocumentHealthcareEntities
    from ._models_py3 import DocumentKeyPhrases
    from ._models_py3 import DocumentLanguage
    from ._models_py3 import DocumentLinkedEntities
    from ._models_py3 import DocumentSentiment
    from ._models_py3 import DocumentStatistics
    from ._models_py3 import EntitiesResult
    from ._models_py3 import EntitiesTask
    from ._models_py3 import EntitiesTaskParameters
    from ._models_py3 import Entity
    from ._models_py3 import EntityLinkingResult
    from ._models_py3 import ErrorResponse
    from ._models_py3 import HealthcareEntity
    from ._models_py3 import HealthcareEntityLink
    from ._models_py3 import HealthcareJobState
    from ._models_py3 import HealthcareRelation
    from ._models_py3 import HealthcareResult
    from ._models_py3 import InnerError
    from ._models_py3 import JobDescriptor
    from ._models_py3 import JobManifest
    from ._models_py3 import JobManifestTasks
    from ._models_py3 import JobMetadata
    from ._models_py3 import KeyPhraseResult
    from ._models_py3 import KeyPhrasesTask
    from ._models_py3 import KeyPhrasesTaskParameters
    from ._models_py3 import LanguageBatchInput
    from ._models_py3 import LanguageInput
    from ._models_py3 import LanguageResult
    from ._models_py3 import LinkedEntity
    from ._models_py3 import Match
    from ._models_py3 import MultiLanguageBatchInput
    from ._models_py3 import MultiLanguageInput
    from ._models_py3 import Pagination
    from ._models_py3 import PiiDocumentEntities
    from ._models_py3 import PiiResult
    from ._models_py3 import PiiTask
    from ._models_py3 import PiiTaskParameters
    from ._models_py3 import RequestStatistics
    from ._models_py3 import SentenceAspect
    from ._models_py3 import SentenceOpinion
    from ._models_py3 import SentenceSentiment
    from ._models_py3 import SentimentConfidenceScorePerLabel
    from ._models_py3 import SentimentResponse
    from ._models_py3 import TaskState
    from ._models_py3 import TasksState
    from ._models_py3 import TasksStateTasks
    from ._models_py3 import TasksStateTasksDetails
    from ._models_py3 import TasksStateTasksEntityRecognitionPiiTasksItem
    from ._models_py3 import TasksStateTasksEntityRecognitionTasksItem
    from ._models_py3 import TasksStateTasksKeyPhraseExtractionActionsItem
    from ._models_py3 import TextAnalyticsError
    from ._models_py3 import TextAnalyticsWarning
except (SyntaxError, ImportError):
    from ._models import AnalyzeBatchInput  # type: ignore
    from ._models import AnalyzeJobState  # type: ignore
    from ._models import AspectConfidenceScoreLabel  # type: ignore
    from ._models import AspectRelation  # type: ignore
    from ._models import Components15Gvwi3SchemasTasksstatePropertiesTasksPropertiesEntityrecognitiontasksItemsAllof1  # type: ignore
    from ._models import Components15X8E9LSchemasTasksstatePropertiesTasksPropertiesEntityrecognitionpiitasksItemsAllof1  # type: ignore
    from ._models import Components1D9IzucSchemasTasksstatePropertiesTasksPropertiesKeyphraseextractiontasksItemsAllof1  # type: ignore
    from ._models import DetectedLanguage  # type: ignore
    from ._models import DocumentEntities  # type: ignore
    from ._models import DocumentError  # type: ignore
    from ._models import DocumentHealthcareEntities  # type: ignore
    from ._models import DocumentKeyPhrases  # type: ignore
    from ._models import DocumentLanguage  # type: ignore
    from ._models import DocumentLinkedEntities  # type: ignore
    from ._models import DocumentSentiment  # type: ignore
    from ._models import DocumentStatistics  # type: ignore
    from ._models import EntitiesResult  # type: ignore
    from ._models import EntitiesTask  # type: ignore
    from ._models import EntitiesTaskParameters  # type: ignore
    from ._models import Entity  # type: ignore
    from ._models import EntityLinkingResult  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import HealthcareEntity  # type: ignore
    from ._models import HealthcareEntityLink  # type: ignore
    from ._models import HealthcareJobState  # type: ignore
    from ._models import HealthcareRelation  # type: ignore
    from ._models import HealthcareResult  # type: ignore
    from ._models import InnerError  # type: ignore
    from ._models import JobDescriptor  # type: ignore
    from ._models import JobManifest  # type: ignore
    from ._models import JobManifestTasks  # type: ignore
    from ._models import JobMetadata  # type: ignore
    from ._models import KeyPhraseResult  # type: ignore
    from ._models import KeyPhrasesTask  # type: ignore
    from ._models import KeyPhrasesTaskParameters  # type: ignore
    from ._models import LanguageBatchInput  # type: ignore
    from ._models import LanguageInput  # type: ignore
    from ._models import LanguageResult  # type: ignore
    from ._models import LinkedEntity  # type: ignore
    from ._models import Match  # type: ignore
    from ._models import MultiLanguageBatchInput  # type: ignore
    from ._models import MultiLanguageInput  # type: ignore
    from ._models import Pagination  # type: ignore
    from ._models import PiiDocumentEntities  # type: ignore
    from ._models import PiiResult  # type: ignore
    from ._models import PiiTask  # type: ignore
    from ._models import PiiTaskParameters  # type: ignore
    from ._models import RequestStatistics  # type: ignore
    from ._models import SentenceAspect  # type: ignore
    from ._models import SentenceOpinion  # type: ignore
    from ._models import SentenceSentiment  # type: ignore
    from ._models import SentimentConfidenceScorePerLabel  # type: ignore
    from ._models import SentimentResponse  # type: ignore
    from ._models import TaskState  # type: ignore
    from ._models import TasksState  # type: ignore
    from ._models import TasksStateTasks  # type: ignore
    from ._models import TasksStateTasksDetails  # type: ignore
    from ._models import TasksStateTasksEntityRecognitionPiiTasksItem  # type: ignore
    from ._models import TasksStateTasksEntityRecognitionTasksItem  # type: ignore
    from ._models import TasksStateTasksKeyPhraseExtractionActionsItem  # type: ignore
    from ._models import TextAnalyticsError  # type: ignore
    from ._models import TextAnalyticsWarning  # type: ignore

from ._text_analytics_client_enums import (
    AspectRelationType,
    DocumentSentimentValue,
    ErrorCodeValue,
    InnerErrorCodeValue,
    PiiTaskParametersDomain,
    SentenceSentimentValue,
    State,
    StringIndexType,
    StringIndexTypeResponse,
    TokenSentimentValue,
    WarningCodeValue,
)

__all__ = [
    'AnalyzeBatchInput',
    'AnalyzeJobState',
    'AspectConfidenceScoreLabel',
    'AspectRelation',
    'Components15Gvwi3SchemasTasksstatePropertiesTasksPropertiesEntityrecognitiontasksItemsAllof1',
    'Components15X8E9LSchemasTasksstatePropertiesTasksPropertiesEntityrecognitionpiitasksItemsAllof1',
    'Components1D9IzucSchemasTasksstatePropertiesTasksPropertiesKeyphraseextractiontasksItemsAllof1',
    'DetectedLanguage',
    'DocumentEntities',
    'DocumentError',
    'DocumentHealthcareEntities',
    'DocumentKeyPhrases',
    'DocumentLanguage',
    'DocumentLinkedEntities',
    'DocumentSentiment',
    'DocumentStatistics',
    'EntitiesResult',
    'EntitiesTask',
    'EntitiesTaskParameters',
    'Entity',
    'EntityLinkingResult',
    'ErrorResponse',
    'HealthcareEntity',
    'HealthcareEntityLink',
    'HealthcareJobState',
    'HealthcareRelation',
    'HealthcareResult',
    'InnerError',
    'JobDescriptor',
    'JobManifest',
    'JobManifestTasks',
    'JobMetadata',
    'KeyPhraseResult',
    'KeyPhrasesTask',
    'KeyPhrasesTaskParameters',
    'LanguageBatchInput',
    'LanguageInput',
    'LanguageResult',
    'LinkedEntity',
    'Match',
    'MultiLanguageBatchInput',
    'MultiLanguageInput',
    'Pagination',
    'PiiDocumentEntities',
    'PiiResult',
    'PiiTask',
    'PiiTaskParameters',
    'RequestStatistics',
    'SentenceAspect',
    'SentenceOpinion',
    'SentenceSentiment',
    'SentimentConfidenceScorePerLabel',
    'SentimentResponse',
    'TaskState',
    'TasksState',
    'TasksStateTasks',
    'TasksStateTasksDetails',
    'TasksStateTasksEntityRecognitionPiiTasksItem',
    'TasksStateTasksEntityRecognitionTasksItem',
    'TasksStateTasksKeyPhraseExtractionActionsItem',
    'TextAnalyticsError',
    'TextAnalyticsWarning',
    'AspectRelationType',
    'DocumentSentimentValue',
    'ErrorCodeValue',
    'InnerErrorCodeValue',
    'PiiTaskParametersDomain',
    'SentenceSentimentValue',
    'State',
    'StringIndexType',
    'StringIndexTypeResponse',
    'TokenSentimentValue',
    'WarningCodeValue',
]
