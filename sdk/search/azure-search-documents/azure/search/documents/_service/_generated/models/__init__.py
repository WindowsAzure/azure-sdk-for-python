# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6257, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AnalyzeRequest
    from ._models_py3 import AnalyzeResult
    from ._models_py3 import AnalyzedTokenInfo
    from ._models_py3 import AsciiFoldingTokenFilter
    from ._models_py3 import AzureActiveDirectoryApplicationCredentials
    from ._models_py3 import BM25Similarity
    from ._models_py3 import CharFilter
    from ._models_py3 import CjkBigramTokenFilter
    from ._models_py3 import ClassicSimilarity
    from ._models_py3 import ClassicTokenizer
    from ._models_py3 import CognitiveServicesAccount
    from ._models_py3 import CognitiveServicesAccountKey
    from ._models_py3 import CommonGramTokenFilter
    from ._models_py3 import ConditionalSkill
    from ._models_py3 import CorsOptions
    from ._models_py3 import CustomAnalyzer
    from ._models_py3 import DataChangeDetectionPolicy
    from ._models_py3 import DataDeletionDetectionPolicy
    from ._models_py3 import DataSourceCredentials
    from ._models_py3 import DefaultCognitiveServicesAccount
    from ._models_py3 import DictionaryDecompounderTokenFilter
    from ._models_py3 import DistanceScoringFunction
    from ._models_py3 import DistanceScoringParameters
    from ._models_py3 import EdgeNGramTokenFilter
    from ._models_py3 import EdgeNGramTokenFilterV2
    from ._models_py3 import EdgeNGramTokenizer
    from ._models_py3 import ElisionTokenFilter
    from ._models_py3 import EntityRecognitionSkill
    from ._models_py3 import FieldMapping
    from ._models_py3 import FieldMappingFunction
    from ._models_py3 import FreshnessScoringFunction
    from ._models_py3 import FreshnessScoringParameters
    from ._models_py3 import GetIndexStatisticsResult
    from ._models_py3 import HighWaterMarkChangeDetectionPolicy
    from ._models_py3 import ImageAnalysisSkill
    from ._models_py3 import IndexerExecutionResult
    from ._models_py3 import IndexingParameters
    from ._models_py3 import IndexingSchedule
    from ._models_py3 import InputFieldMappingEntry
    from ._models_py3 import KeepTokenFilter
    from ._models_py3 import KeyPhraseExtractionSkill
    from ._models_py3 import KeywordMarkerTokenFilter
    from ._models_py3 import KeywordTokenizer
    from ._models_py3 import KeywordTokenizerV2
    from ._models_py3 import LanguageDetectionSkill
    from ._models_py3 import LengthTokenFilter
    from ._models_py3 import LexicalAnalyzer
    from ._models_py3 import LexicalTokenizer
    from ._models_py3 import LimitTokenFilter
    from ._models_py3 import ListDataSourcesResult
    from ._models_py3 import ListIndexersResult
    from ._models_py3 import ListIndexesResult
    from ._models_py3 import ListSkillsetsResult
    from ._models_py3 import ListSynonymMapsResult
    from ._models_py3 import LuceneStandardAnalyzer
    from ._models_py3 import LuceneStandardTokenizer
    from ._models_py3 import LuceneStandardTokenizerV2
    from ._models_py3 import MagnitudeScoringFunction
    from ._models_py3 import MagnitudeScoringParameters
    from ._models_py3 import MappingCharFilter
    from ._models_py3 import MergeSkill
    from ._models_py3 import MicrosoftLanguageStemmingTokenizer
    from ._models_py3 import MicrosoftLanguageTokenizer
    from ._models_py3 import NGramTokenFilter
    from ._models_py3 import NGramTokenFilterV2
    from ._models_py3 import NGramTokenizer
    from ._models_py3 import OcrSkill
    from ._models_py3 import OutputFieldMappingEntry
    from ._models_py3 import PathHierarchyTokenizerV2
    from ._models_py3 import PatternAnalyzer
    from ._models_py3 import PatternCaptureTokenFilter
    from ._models_py3 import PatternReplaceCharFilter
    from ._models_py3 import PatternReplaceTokenFilter
    from ._models_py3 import PatternTokenizer
    from ._models_py3 import PhoneticTokenFilter
    from ._models_py3 import RequestOptions
    from ._models_py3 import ResourceCounter
    from ._models_py3 import ScoringFunction
    from ._models_py3 import ScoringProfile
    from ._models_py3 import SearchError
    from ._models_py3 import SearchField
    from ._models_py3 import SearchIndex
    from ._models_py3 import SearchIndexer
    from ._models_py3 import SearchIndexerDataContainer
    from ._models_py3 import SearchIndexerDataSource
    from ._models_py3 import SearchIndexerError
    from ._models_py3 import SearchIndexerLimits
    from ._models_py3 import SearchIndexerSkill
    from ._models_py3 import SearchIndexerSkillset
    from ._models_py3 import SearchIndexerStatus
    from ._models_py3 import SearchIndexerWarning
    from ._models_py3 import SearchResourceEncryptionKey
    from ._models_py3 import SentimentSkill
    from ._models_py3 import ServiceCounters
    from ._models_py3 import ServiceLimits
    from ._models_py3 import ServiceStatistics
    from ._models_py3 import ShaperSkill
    from ._models_py3 import ShingleTokenFilter
    from ._models_py3 import Similarity
    from ._models_py3 import SnowballTokenFilter
    from ._models_py3 import SoftDeleteColumnDeletionDetectionPolicy
    from ._models_py3 import SplitSkill
    from ._models_py3 import SqlIntegratedChangeTrackingPolicy
    from ._models_py3 import StemmerOverrideTokenFilter
    from ._models_py3 import StemmerTokenFilter
    from ._models_py3 import StopAnalyzer
    from ._models_py3 import StopwordsTokenFilter
    from ._models_py3 import Suggester
    from ._models_py3 import SynonymMap
    from ._models_py3 import SynonymTokenFilter
    from ._models_py3 import TagScoringFunction
    from ._models_py3 import TagScoringParameters
    from ._models_py3 import TextTranslationSkill
    from ._models_py3 import TextWeights
    from ._models_py3 import TokenFilter
    from ._models_py3 import TruncateTokenFilter
    from ._models_py3 import UaxUrlEmailTokenizer
    from ._models_py3 import UniqueTokenFilter
    from ._models_py3 import WebApiSkill
    from ._models_py3 import WordDelimiterTokenFilter
except (SyntaxError, ImportError):
    from ._models import AnalyzeRequest  # type: ignore
    from ._models import AnalyzeResult  # type: ignore
    from ._models import AnalyzedTokenInfo  # type: ignore
    from ._models import AsciiFoldingTokenFilter  # type: ignore
    from ._models import AzureActiveDirectoryApplicationCredentials  # type: ignore
    from ._models import BM25Similarity  # type: ignore
    from ._models import CharFilter  # type: ignore
    from ._models import CjkBigramTokenFilter  # type: ignore
    from ._models import ClassicSimilarity  # type: ignore
    from ._models import ClassicTokenizer  # type: ignore
    from ._models import CognitiveServicesAccount  # type: ignore
    from ._models import CognitiveServicesAccountKey  # type: ignore
    from ._models import CommonGramTokenFilter  # type: ignore
    from ._models import ConditionalSkill  # type: ignore
    from ._models import CorsOptions  # type: ignore
    from ._models import CustomAnalyzer  # type: ignore
    from ._models import DataChangeDetectionPolicy  # type: ignore
    from ._models import DataDeletionDetectionPolicy  # type: ignore
    from ._models import DataSourceCredentials  # type: ignore
    from ._models import DefaultCognitiveServicesAccount  # type: ignore
    from ._models import DictionaryDecompounderTokenFilter  # type: ignore
    from ._models import DistanceScoringFunction  # type: ignore
    from ._models import DistanceScoringParameters  # type: ignore
    from ._models import EdgeNGramTokenFilter  # type: ignore
    from ._models import EdgeNGramTokenFilterV2  # type: ignore
    from ._models import EdgeNGramTokenizer  # type: ignore
    from ._models import ElisionTokenFilter  # type: ignore
    from ._models import EntityRecognitionSkill  # type: ignore
    from ._models import FieldMapping  # type: ignore
    from ._models import FieldMappingFunction  # type: ignore
    from ._models import FreshnessScoringFunction  # type: ignore
    from ._models import FreshnessScoringParameters  # type: ignore
    from ._models import GetIndexStatisticsResult  # type: ignore
    from ._models import HighWaterMarkChangeDetectionPolicy  # type: ignore
    from ._models import ImageAnalysisSkill  # type: ignore
    from ._models import IndexerExecutionResult  # type: ignore
    from ._models import IndexingParameters  # type: ignore
    from ._models import IndexingSchedule  # type: ignore
    from ._models import InputFieldMappingEntry  # type: ignore
    from ._models import KeepTokenFilter  # type: ignore
    from ._models import KeyPhraseExtractionSkill  # type: ignore
    from ._models import KeywordMarkerTokenFilter  # type: ignore
    from ._models import KeywordTokenizer  # type: ignore
    from ._models import KeywordTokenizerV2  # type: ignore
    from ._models import LanguageDetectionSkill  # type: ignore
    from ._models import LengthTokenFilter  # type: ignore
    from ._models import LexicalAnalyzer  # type: ignore
    from ._models import LexicalTokenizer  # type: ignore
    from ._models import LimitTokenFilter  # type: ignore
    from ._models import ListDataSourcesResult  # type: ignore
    from ._models import ListIndexersResult  # type: ignore
    from ._models import ListIndexesResult  # type: ignore
    from ._models import ListSkillsetsResult  # type: ignore
    from ._models import ListSynonymMapsResult  # type: ignore
    from ._models import LuceneStandardAnalyzer  # type: ignore
    from ._models import LuceneStandardTokenizer  # type: ignore
    from ._models import LuceneStandardTokenizerV2  # type: ignore
    from ._models import MagnitudeScoringFunction  # type: ignore
    from ._models import MagnitudeScoringParameters  # type: ignore
    from ._models import MappingCharFilter  # type: ignore
    from ._models import MergeSkill  # type: ignore
    from ._models import MicrosoftLanguageStemmingTokenizer  # type: ignore
    from ._models import MicrosoftLanguageTokenizer  # type: ignore
    from ._models import NGramTokenFilter  # type: ignore
    from ._models import NGramTokenFilterV2  # type: ignore
    from ._models import NGramTokenizer  # type: ignore
    from ._models import OcrSkill  # type: ignore
    from ._models import OutputFieldMappingEntry  # type: ignore
    from ._models import PathHierarchyTokenizerV2  # type: ignore
    from ._models import PatternAnalyzer  # type: ignore
    from ._models import PatternCaptureTokenFilter  # type: ignore
    from ._models import PatternReplaceCharFilter  # type: ignore
    from ._models import PatternReplaceTokenFilter  # type: ignore
    from ._models import PatternTokenizer  # type: ignore
    from ._models import PhoneticTokenFilter  # type: ignore
    from ._models import RequestOptions  # type: ignore
    from ._models import ResourceCounter  # type: ignore
    from ._models import ScoringFunction  # type: ignore
    from ._models import ScoringProfile  # type: ignore
    from ._models import SearchError  # type: ignore
    from ._models import SearchField  # type: ignore
    from ._models import SearchIndex  # type: ignore
    from ._models import SearchIndexer  # type: ignore
    from ._models import SearchIndexerDataContainer  # type: ignore
    from ._models import SearchIndexerDataSource  # type: ignore
    from ._models import SearchIndexerError  # type: ignore
    from ._models import SearchIndexerLimits  # type: ignore
    from ._models import SearchIndexerSkill  # type: ignore
    from ._models import SearchIndexerSkillset  # type: ignore
    from ._models import SearchIndexerStatus  # type: ignore
    from ._models import SearchIndexerWarning  # type: ignore
    from ._models import SearchResourceEncryptionKey  # type: ignore
    from ._models import SentimentSkill  # type: ignore
    from ._models import ServiceCounters  # type: ignore
    from ._models import ServiceLimits  # type: ignore
    from ._models import ServiceStatistics  # type: ignore
    from ._models import ShaperSkill  # type: ignore
    from ._models import ShingleTokenFilter  # type: ignore
    from ._models import Similarity  # type: ignore
    from ._models import SnowballTokenFilter  # type: ignore
    from ._models import SoftDeleteColumnDeletionDetectionPolicy  # type: ignore
    from ._models import SplitSkill  # type: ignore
    from ._models import SqlIntegratedChangeTrackingPolicy  # type: ignore
    from ._models import StemmerOverrideTokenFilter  # type: ignore
    from ._models import StemmerTokenFilter  # type: ignore
    from ._models import StopAnalyzer  # type: ignore
    from ._models import StopwordsTokenFilter  # type: ignore
    from ._models import Suggester  # type: ignore
    from ._models import SynonymMap  # type: ignore
    from ._models import SynonymTokenFilter  # type: ignore
    from ._models import TagScoringFunction  # type: ignore
    from ._models import TagScoringParameters  # type: ignore
    from ._models import TextTranslationSkill  # type: ignore
    from ._models import TextWeights  # type: ignore
    from ._models import TokenFilter  # type: ignore
    from ._models import TruncateTokenFilter  # type: ignore
    from ._models import UaxUrlEmailTokenizer  # type: ignore
    from ._models import UniqueTokenFilter  # type: ignore
    from ._models import WebApiSkill  # type: ignore
    from ._models import WordDelimiterTokenFilter  # type: ignore

from ._search_service_client_enums import (
    CjkBigramTokenFilterScripts,
    EdgeNGramTokenFilterSide,
    EntityCategory,
    EntityRecognitionSkillLanguage,
    ImageAnalysisSkillLanguage,
    ImageDetail,
    IndexerExecutionStatus,
    IndexerStatus,
    KeyPhraseExtractionSkillLanguage,
    LexicalAnalyzerName,
    LexicalTokenizerName,
    MicrosoftStemmingTokenizerLanguage,
    MicrosoftTokenizerLanguage,
    OcrSkillLanguage,
    PhoneticEncoder,
    RegexFlags,
    ScoringFunctionAggregation,
    ScoringFunctionInterpolation,
    SearchFieldDataType,
    SearchIndexerDataSourceType,
    SentimentSkillLanguage,
    SnowballTokenFilterLanguage,
    SplitSkillLanguage,
    StemmerTokenFilterLanguage,
    StopwordsList,
    TextExtractionAlgorithm,
    TextSplitMode,
    TextTranslationSkillLanguage,
    TokenCharacterKind,
    TokenFilterName,
    VisualFeature,
)

__all__ = [
    'AnalyzeRequest',
    'AnalyzeResult',
    'AnalyzedTokenInfo',
    'AsciiFoldingTokenFilter',
    'AzureActiveDirectoryApplicationCredentials',
    'BM25Similarity',
    'CharFilter',
    'CjkBigramTokenFilter',
    'ClassicSimilarity',
    'ClassicTokenizer',
    'CognitiveServicesAccount',
    'CognitiveServicesAccountKey',
    'CommonGramTokenFilter',
    'ConditionalSkill',
    'CorsOptions',
    'CustomAnalyzer',
    'DataChangeDetectionPolicy',
    'DataDeletionDetectionPolicy',
    'DataSourceCredentials',
    'DefaultCognitiveServicesAccount',
    'DictionaryDecompounderTokenFilter',
    'DistanceScoringFunction',
    'DistanceScoringParameters',
    'EdgeNGramTokenFilter',
    'EdgeNGramTokenFilterV2',
    'EdgeNGramTokenizer',
    'ElisionTokenFilter',
    'EntityRecognitionSkill',
    'FieldMapping',
    'FieldMappingFunction',
    'FreshnessScoringFunction',
    'FreshnessScoringParameters',
    'GetIndexStatisticsResult',
    'HighWaterMarkChangeDetectionPolicy',
    'ImageAnalysisSkill',
    'IndexerExecutionResult',
    'IndexingParameters',
    'IndexingSchedule',
    'InputFieldMappingEntry',
    'KeepTokenFilter',
    'KeyPhraseExtractionSkill',
    'KeywordMarkerTokenFilter',
    'KeywordTokenizer',
    'KeywordTokenizerV2',
    'LanguageDetectionSkill',
    'LengthTokenFilter',
    'LexicalAnalyzer',
    'LexicalTokenizer',
    'LimitTokenFilter',
    'ListDataSourcesResult',
    'ListIndexersResult',
    'ListIndexesResult',
    'ListSkillsetsResult',
    'ListSynonymMapsResult',
    'LuceneStandardAnalyzer',
    'LuceneStandardTokenizer',
    'LuceneStandardTokenizerV2',
    'MagnitudeScoringFunction',
    'MagnitudeScoringParameters',
    'MappingCharFilter',
    'MergeSkill',
    'MicrosoftLanguageStemmingTokenizer',
    'MicrosoftLanguageTokenizer',
    'NGramTokenFilter',
    'NGramTokenFilterV2',
    'NGramTokenizer',
    'OcrSkill',
    'OutputFieldMappingEntry',
    'PathHierarchyTokenizerV2',
    'PatternAnalyzer',
    'PatternCaptureTokenFilter',
    'PatternReplaceCharFilter',
    'PatternReplaceTokenFilter',
    'PatternTokenizer',
    'PhoneticTokenFilter',
    'RequestOptions',
    'ResourceCounter',
    'ScoringFunction',
    'ScoringProfile',
    'SearchError',
    'SearchField',
    'SearchIndex',
    'SearchIndexer',
    'SearchIndexerDataContainer',
    'SearchIndexerDataSource',
    'SearchIndexerError',
    'SearchIndexerLimits',
    'SearchIndexerSkill',
    'SearchIndexerSkillset',
    'SearchIndexerStatus',
    'SearchIndexerWarning',
    'SearchResourceEncryptionKey',
    'SentimentSkill',
    'ServiceCounters',
    'ServiceLimits',
    'ServiceStatistics',
    'ShaperSkill',
    'ShingleTokenFilter',
    'Similarity',
    'SnowballTokenFilter',
    'SoftDeleteColumnDeletionDetectionPolicy',
    'SplitSkill',
    'SqlIntegratedChangeTrackingPolicy',
    'StemmerOverrideTokenFilter',
    'StemmerTokenFilter',
    'StopAnalyzer',
    'StopwordsTokenFilter',
    'Suggester',
    'SynonymMap',
    'SynonymTokenFilter',
    'TagScoringFunction',
    'TagScoringParameters',
    'TextTranslationSkill',
    'TextWeights',
    'TokenFilter',
    'TruncateTokenFilter',
    'UaxUrlEmailTokenizer',
    'UniqueTokenFilter',
    'WebApiSkill',
    'WordDelimiterTokenFilter',
    'CjkBigramTokenFilterScripts',
    'EdgeNGramTokenFilterSide',
    'EntityCategory',
    'EntityRecognitionSkillLanguage',
    'ImageAnalysisSkillLanguage',
    'ImageDetail',
    'IndexerExecutionStatus',
    'IndexerStatus',
    'KeyPhraseExtractionSkillLanguage',
    'LexicalAnalyzerName',
    'LexicalTokenizerName',
    'MicrosoftStemmingTokenizerLanguage',
    'MicrosoftTokenizerLanguage',
    'OcrSkillLanguage',
    'PhoneticEncoder',
    'RegexFlags',
    'ScoringFunctionAggregation',
    'ScoringFunctionInterpolation',
    'SearchFieldDataType',
    'SearchIndexerDataSourceType',
    'SentimentSkillLanguage',
    'SnowballTokenFilterLanguage',
    'SplitSkillLanguage',
    'StemmerTokenFilterLanguage',
    'StopwordsList',
    'TextExtractionAlgorithm',
    'TextSplitMode',
    'TextTranslationSkillLanguage',
    'TokenCharacterKind',
    'TokenFilterName',
    'VisualFeature',
]
