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
    SearchIndexClient,
    SearchItemPaged,
    SearchQuery,
    SuggestQuery,
    odata,
)
from ._service import SearchServiceClient
from ._service._generated.models import (
    Analyzer,
    AnalyzeRequest,
    AnalyzeResult,
    AsciiFoldingTokenFilter,
    AzureActiveDirectoryApplicationCredentials,
    CharFilter,
    CjkBigramTokenFilter,
    ClassicTokenizer,
    CommonGramTokenFilter,
    CorsOptions,
    CustomAnalyzer,
    DictionaryDecompounderTokenFilter,
    DistanceScoringFunction,
    DistanceScoringParameters,
    EdgeNGramTokenFilter,
    EdgeNGramTokenizer,
    ElisionTokenFilter,
    EncryptionKey,
    Field,
    FreshnessScoringFunction,
    FreshnessScoringParameters,
    GetIndexStatisticsResult,
    Index,
    KeepTokenFilter,
    KeywordMarkerTokenFilter,
    KeywordTokenizer,
    LengthTokenFilter,
    LimitTokenFilter,
    MagnitudeScoringFunction,
    MagnitudeScoringParameters,
    MappingCharFilter,
    MicrosoftLanguageStemmingTokenizer,
    MicrosoftLanguageTokenizer,
    NGramTokenFilter,
    NGramTokenizer,
    PatternCaptureTokenFilter,
    PatternReplaceCharFilter,
    PatternReplaceTokenFilter,
    PhoneticTokenFilter,
    RegexFlags,
    ScoringFunction,
    ScoringProfile,
    ShingleTokenFilter,
    SnowballTokenFilter,
    StandardAnalyzer,
    StandardTokenizer,
    StemmerOverrideTokenFilter,
    StemmerTokenFilter,
    StopAnalyzer,
    StopwordsTokenFilter,
    Suggester,
    SynonymTokenFilter,
    TagScoringFunction,
    TagScoringParameters,
    TextWeights,
    TokenFilter,
    TokenInfo,
    Tokenizer,
    TruncateTokenFilter,
    UaxUrlEmailTokenizer,
    UniqueTokenFilter,
    WordDelimiterTokenFilter,
)
from ._service._models import PatternAnalyzer, PatternTokenizer
from ._version import VERSION

__version__ = VERSION


__all__ = (
    "AnalyzeRequest",
    "AnalyzeResult",
    "Analyzer",
    "AsciiFoldingTokenFilter",
    "AutocompleteQuery",
    "AzureActiveDirectoryApplicationCredentials",
    "CharFilter",
    "CjkBigramTokenFilter",
    "ClassicTokenizer",
    "CommonGramTokenFilter",
    "CorsOptions",
    "CustomAnalyzer",
    "DictionaryDecompounderTokenFilter",
    "DistanceScoringFunction",
    "DistanceScoringParameters",
    "EdgeNGramTokenFilter",
    "EdgeNGramTokenizer",
    "ElisionTokenFilter",
    "EncryptionKey",
    "Field",
    "FreshnessScoringFunction",
    "FreshnessScoringParameters",
    "GetIndexStatisticsResult",
    "Index",
    "IndexAction",
    "IndexDocumentsBatch",
    "IndexingResult",
    "KeepTokenFilter",
    "KeywordMarkerTokenFilter",
    "KeywordTokenizer",
    "LengthTokenFilter",
    "LimitTokenFilter",
    "MagnitudeScoringFunction",
    "MagnitudeScoringParameters",
    "MappingCharFilter",
    "MicrosoftLanguageStemmingTokenizer",
    "MicrosoftLanguageTokenizer",
    "NGramTokenFilter",
    "NGramTokenizer",
    "PatternAnalyzer",
    "PatternCaptureTokenFilter",
    "PatternReplaceCharFilter",
    "PatternReplaceTokenFilter",
    "PatternTokenizer",
    "PhoneticTokenFilter",
    "RegexFlags",
    "ScoringFunction",
    "ScoringProfile",
    "SearchIndexClient",
    "SearchItemPaged",
    "SearchQuery",
    "SearchServiceClient",
    "ShingleTokenFilter",
    "SnowballTokenFilter",
    "StandardAnalyzer",
    "StandardTokenizer",
    "StemmerOverrideTokenFilter",
    "StemmerTokenFilter",
    "StopAnalyzer",
    "StopwordsTokenFilter",
    "SuggestQuery",
    "Suggester",
    "SynonymTokenFilter",
    "TagScoringFunction",
    "TagScoringParameters",
    "TextWeights",
    "TokenFilter",
    "TokenInfo",
    "Tokenizer",
    "TruncateTokenFilter",
    "UaxUrlEmailTokenizer",
    "UniqueTokenFilter",
    "WordDelimiterTokenFilter",
    "odata",
)
