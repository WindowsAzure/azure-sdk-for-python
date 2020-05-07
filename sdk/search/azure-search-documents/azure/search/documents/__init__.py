# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

from ._index import (
    AutocompleteQuery,
    IndexAction,
    IndexDocumentsBatch,
    IndexingResult,
    SearchClient,
    SearchItemPaged,
    SearchQuery,
    SuggestQuery,
    odata,
)
from ._service import (
    ComplexField,
    SearchableField,
    SimpleField,
    SearchServiceClient,
    edm,
)
from ._service._generated.models import (
    AnalyzeRequest,
    AnalyzeResult,
    AsciiFoldingTokenFilter,
    AzureActiveDirectoryApplicationCredentials,
    CharFilter,
    CjkBigramTokenFilter,
    ClassicTokenizer,
    CommonGramTokenFilter,
    ConditionalSkill,
    CorsOptions,
    CustomAnalyzer,
    DataSource,
    DataSourceCredentials,
    DataContainer,
    DictionaryDecompounderTokenFilter,
    DistanceScoringFunction,
    DistanceScoringParameters,
    EdgeNGramTokenFilter,
    EdgeNGramTokenizer,
    ElisionTokenFilter,
    EncryptionKey,
    EntityRecognitionSkill,
    Field,
    FreshnessScoringFunction,
    FreshnessScoringParameters,
    GetIndexStatisticsResult,
    ImageAnalysisSkill,
    Index,
    Indexer,
    InputFieldMappingEntry,
    KeepTokenFilter,
    KeyPhraseExtractionSkill,
    KeywordMarkerTokenFilter,
    KeywordTokenizer,
    LanguageDetectionSkill,
    LengthTokenFilter,
    LexicalAnalyzer,
    LimitTokenFilter,
    LuceneStandardAnalyzer,
    LuceneStandardTokenizer,
    MagnitudeScoringFunction,
    MagnitudeScoringParameters,
    MappingCharFilter,
    MergeSkill,
    MicrosoftLanguageStemmingTokenizer,
    MicrosoftLanguageTokenizer,
    NGramTokenFilter,
    NGramTokenizer,
    OcrSkill,
    OutputFieldMappingEntry,
    PatternCaptureTokenFilter,
    PatternReplaceCharFilter,
    PatternReplaceTokenFilter,
    PhoneticTokenFilter,
    RegexFlags,
    ScoringFunction,
    ScoringProfile,
    SentimentSkill,
    ShaperSkill,
    ShingleTokenFilter,
    Skillset,
    SnowballTokenFilter,
    SplitSkill,
    StemmerOverrideTokenFilter,
    StemmerTokenFilter,
    StopAnalyzer,
    StopwordsTokenFilter,
    Suggester,
    SynonymMap,
    SynonymTokenFilter,
    TagScoringFunction,
    TagScoringParameters,
    TextTranslationSkill,
    TextWeights,
    TokenFilter,
    TokenInfo,
    Tokenizer,
    TruncateTokenFilter,
    UaxUrlEmailTokenizer,
    UniqueTokenFilter,
    WebApiSkill,
    WordDelimiterTokenFilter,
)
from ._service._models import PatternAnalyzer, PatternTokenizer
from ._version import VERSION

__version__ = VERSION


__all__ = (
    "AnalyzeRequest",
    "AnalyzeResult",
    "AsciiFoldingTokenFilter",
    "AutocompleteQuery",
    "AzureActiveDirectoryApplicationCredentials",
    "CharFilter",
    "CjkBigramTokenFilter",
    "ClassicTokenizer",
    "CommonGramTokenFilter",
    "ComplexField",
    "ConditionalSkill",
    "CorsOptions",
    "CustomAnalyzer",
    "DataSource",
    "DataSourceCredentials",
    "DataContainer",
    "DictionaryDecompounderTokenFilter",
    "DistanceScoringFunction",
    "DistanceScoringParameters",
    "EdgeNGramTokenFilter",
    "EdgeNGramTokenizer",
    "ElisionTokenFilter",
    "EncryptionKey",
    "EntityRecognitionSkill",
    "Field",
    "FreshnessScoringFunction",
    "FreshnessScoringParameters",
    "GetIndexStatisticsResult",
    "ImageAnalysisSkill",
    "Index",
    "Indexer",
    "IndexAction",
    "IndexDocumentsBatch",
    "IndexingResult",
    "InputFieldMappingEntry",
    "KeepTokenFilter",
    "KeyPhraseExtractionSkill",
    "KeywordMarkerTokenFilter",
    "KeywordTokenizer",
    "LanguageDetectionSkill",
    "LengthTokenFilter",
    "LexicalAnalyzer",
    "LimitTokenFilter",
    "LuceneStandardAnalyzer",
    "LuceneStandardTokenizer",
    "MagnitudeScoringFunction",
    "MagnitudeScoringParameters",
    "MappingCharFilter",
    "MergeSkill",
    "MicrosoftLanguageStemmingTokenizer",
    "MicrosoftLanguageTokenizer",
    "NGramTokenFilter",
    "NGramTokenizer",
    "OcrSkill",
    "OutputFieldMappingEntry",
    "PatternAnalyzer",
    "PatternCaptureTokenFilter",
    "PatternReplaceCharFilter",
    "PatternReplaceTokenFilter",
    "PatternTokenizer",
    "PhoneticTokenFilter",
    "RegexFlags",
    "ScoringFunction",
    "ScoringProfile",
    "SearchClient",
    "SearchItemPaged",
    "SearchQuery",
    "SearchServiceClient",
    "SearchableField",
    "SentimentSkill",
    "ShaperSkill",
    "ShingleTokenFilter",
    "SimpleField",
    "Skillset",
    "SnowballTokenFilter",
    "SplitSkill",
    "StemmerOverrideTokenFilter",
    "StemmerTokenFilter",
    "StopAnalyzer",
    "StopwordsTokenFilter",
    "SuggestQuery",
    "Suggester",
    "SynonymMap",
    "SynonymTokenFilter",
    "TagScoringFunction",
    "TagScoringParameters",
    "TextTranslationSkill",
    "TextWeights",
    "TokenFilter",
    "TokenInfo",
    "Tokenizer",
    "TruncateTokenFilter",
    "UaxUrlEmailTokenizer",
    "UniqueTokenFilter",
    "WebApiSkill",
    "WordDelimiterTokenFilter",
    "edm",
    "odata",
)
