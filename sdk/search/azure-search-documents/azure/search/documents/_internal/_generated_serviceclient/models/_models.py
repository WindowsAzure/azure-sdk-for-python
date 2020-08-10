# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import msrest.serialization


class TokenFilter(msrest.serialization.Model):
    """Base type for token filters.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AsciiFoldingTokenFilter, CjkBigramTokenFilter, CommonGramTokenFilter,
    DictionaryDecompounderTokenFilter, EdgeNGramTokenFilter, EdgeNGramTokenFilterV2,
    ElisionTokenFilter, KeepTokenFilter, KeywordMarkerTokenFilter, LengthTokenFilter,
    LimitTokenFilter, NGramTokenFilter, NGramTokenFilterV2, PatternCaptureTokenFilter,
    PatternReplaceTokenFilter, PhoneticTokenFilter, ShingleTokenFilter, SnowballTokenFilter,
    StemmerOverrideTokenFilter, StemmerTokenFilter, StopwordsTokenFilter, SynonymTokenFilter,
    TruncateTokenFilter, UniqueTokenFilter, WordDelimiterTokenFilter.

    All required parameters must be populated in order to send to Azure.

    :param odata_type: Required. Identifies the concrete type of the token filter.Constant filled
     by server.
    :type odata_type: str
    :param name: Required. The name of the token filter. It must only contain letters, digits,
     spaces, dashes or underscores, can only start and end with alphanumeric characters, and is
     limited to 128 characters.
    :type name: str
    """

    _validation = {
        'odata_type': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'odata_type': {'key': '@odata\\.type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    _subtype_map = {
        'odata_type': {
            '#Microsoft.Azure.Search.AsciiFoldingTokenFilter': 'AsciiFoldingTokenFilter',
            '#Microsoft.Azure.Search.CjkBigramTokenFilter': 'CjkBigramTokenFilter',
            '#Microsoft.Azure.Search.CommonGramTokenFilter': 'CommonGramTokenFilter',
            '#Microsoft.Azure.Search.DictionaryDecompounderTokenFilter': 'DictionaryDecompounderTokenFilter',
            '#Microsoft.Azure.Search.EdgeNGramTokenFilter': 'EdgeNGramTokenFilter',
            '#Microsoft.Azure.Search.EdgeNGramTokenFilterV2': 'EdgeNGramTokenFilterV2',
            '#Microsoft.Azure.Search.ElisionTokenFilter': 'ElisionTokenFilter',
            '#Microsoft.Azure.Search.KeepTokenFilter': 'KeepTokenFilter',
            '#Microsoft.Azure.Search.KeywordMarkerTokenFilter': 'KeywordMarkerTokenFilter',
            '#Microsoft.Azure.Search.LengthTokenFilter': 'LengthTokenFilter',
            '#Microsoft.Azure.Search.LimitTokenFilter': 'LimitTokenFilter',
            '#Microsoft.Azure.Search.NGramTokenFilter': 'NGramTokenFilter',
            '#Microsoft.Azure.Search.NGramTokenFilterV2': 'NGramTokenFilterV2',
            '#Microsoft.Azure.Search.PatternCaptureTokenFilter': 'PatternCaptureTokenFilter',
            '#Microsoft.Azure.Search.PatternReplaceTokenFilter': 'PatternReplaceTokenFilter',
            '#Microsoft.Azure.Search.PhoneticTokenFilter': 'PhoneticTokenFilter',
            '#Microsoft.Azure.Search.ShingleTokenFilter': 'ShingleTokenFilter',
            '#Microsoft.Azure.Search.SnowballTokenFilter': 'SnowballTokenFilter',
            '#Microsoft.Azure.Search.StemmerOverrideTokenFilter': 'StemmerOverrideTokenFilter',
            '#Microsoft.Azure.Search.StemmerTokenFilter': 'StemmerTokenFilter',
            '#Microsoft.Azure.Search.StopwordsTokenFilter': 'StopwordsTokenFilter',
            '#Microsoft.Azure.Search.SynonymTokenFilter': 'SynonymTokenFilter',
            '#Microsoft.Azure.Search.TruncateTokenFilter': 'TruncateTokenFilter',
            '#Microsoft.Azure.Search.UniqueTokenFilter': 'UniqueTokenFilter',
            '#Microsoft.Azure.Search.WordDelimiterTokenFilter': 'WordDelimiterTokenFilter'
        }
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TokenFilter, self).__init__(**kwargs)
        self.odata_type = None  # type: Optional[str]
        self.name = kwargs['name']


class Similarity(msrest.serialization.Model):
    """Base type for similarity algorithms. Similarity algorithms are used to calculate scores that tie queries
    to documents. The higher the score, the more relevant the document is to that specific query.
    Those scores are used to rank the search results.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: BM25Similarity, ClassicSimilarity.

    All required parameters must be populated in order to send to Azure.

    :param odata_type: Required. Constant filled by server.
    :type odata_type: str
    """

    _validation = {
        'odata_type': {'required': True},
    }

    _attribute_map = {
        'odata_type': {'key': '@odata\\.type', 'type': 'str'},
    }

    _subtype_map = {
        'odata_type': {'#Microsoft.Azure.Search.BM25Similarity': 'BM25Similarity',
                       '#Microsoft.Azure.Search.ClassicSimilarity': 'ClassicSimilarity'}
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Similarity, self).__init__(**kwargs)
        self.odata_type = None  # type: Optional[str]


class LexicalTokenizer(msrest.serialization.Model):
    """Base type for tokenizers.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: ClassicTokenizer, EdgeNGramTokenizer, KeywordTokenizer, KeywordTokenizerV2,
    MicrosoftLanguageStemmingTokenizer, MicrosoftLanguageTokenizer, NGramTokenizer,
    PathHierarchyTokenizerV2, PatternTokenizer, LuceneStandardTokenizer, LuceneStandardTokenizerV2,
    UaxUrlEmailTokenizer.

    All required parameters must be populated in order to send to Azure.

    :param odata_type: Required. Identifies the concrete type of the tokenizer.Constant filled by
     server.
    :type odata_type: str
    :param name: Required. The name of the tokenizer. It must only contain letters, digits, spaces,
     dashes or underscores, can only start and end with alphanumeric characters, and is limited to
     128 characters.
    :type name: str
    """

    _validation = {
        'odata_type': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'odata_type': {'key': '@odata\\.type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    _subtype_map = {
        'odata_type': {
            '#Microsoft.Azure.Search.ClassicTokenizer': 'ClassicTokenizer',
            '#Microsoft.Azure.Search.EdgeNGramTokenizer': 'EdgeNGramTokenizer',
            '#Microsoft.Azure.Search.KeywordTokenizer': 'KeywordTokenizer',
            '#Microsoft.Azure.Search.KeywordTokenizerV2': 'KeywordTokenizerV2',
            '#Microsoft.Azure.Search.MicrosoftLanguageStemmingTokenizer': 'MicrosoftLanguageStemmingTokenizer',
            '#Microsoft.Azure.Search.MicrosoftLanguageTokenizer': 'MicrosoftLanguageTokenizer',
            '#Microsoft.Azure.Search.NGramTokenizer': 'NGramTokenizer',
            '#Microsoft.Azure.Search.PathHierarchyTokenizerV2': 'PathHierarchyTokenizerV2',
            '#Microsoft.Azure.Search.PatternTokenizer': 'PatternTokenizer',
            '#Microsoft.Azure.Search.StandardTokenizer': 'LuceneStandardTokenizer',
            '#Microsoft.Azure.Search.StandardTokenizerV2': 'LuceneStandardTokenizerV2',
            '#Microsoft.Azure.Search.UaxUrlEmailTokenizer': 'UaxUrlEmailTokenizer'
        }
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LexicalTokenizer, self).__init__(**kwargs)
        self.odata_type = None  # type: Optional[str]
        self.name = kwargs['name']


class CorsOptions(msrest.serialization.Model):
    """Defines options to control Cross-Origin Resource Sharing (CORS) for an index.

    All required parameters must be populated in order to send to Azure.

    :param allowed_origins: Required. The list of origins from which JavaScript code will be
     granted access to your index. Can contain a list of hosts of the form {protocol}://{fully-
     qualified-domain-name}[:{port#}], or a single '*' to allow all origins (not recommended).
    :type allowed_origins: list[str]
    :param max_age_in_seconds: The duration for which browsers should cache CORS preflight
     responses. Defaults to 5 minutes.
    :type max_age_in_seconds: long
    """

    _validation = {
        'allowed_origins': {'required': True},
    }

    _attribute_map = {
        'allowed_origins': {'key': 'allowedOrigins', 'type': '[str]'},
        'max_age_in_seconds': {'key': 'maxAgeInSeconds', 'type': 'long'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CorsOptions, self).__init__(**kwargs)
        self.allowed_origins = kwargs['allowed_origins']
        self.max_age_in_seconds = kwargs.get('max_age_in_seconds', None)


class LexicalAnalyzer(msrest.serialization.Model):
    """Base type for analyzers.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: CustomAnalyzer, PatternAnalyzer, LuceneStandardAnalyzer, StopAnalyzer.

    All required parameters must be populated in order to send to Azure.

    :param odata_type: Required. Identifies the concrete type of the analyzer.Constant filled by
     server.
    :type odata_type: str
    :param name: Required. The name of the analyzer. It must only contain letters, digits, spaces,
     dashes or underscores, can only start and end with alphanumeric characters, and is limited to
     128 characters.
    :type name: str
    """

    _validation = {
        'odata_type': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'odata_type': {'key': '@odata\\.type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    _subtype_map = {
        'odata_type': {
            '#Microsoft.Azure.Search.CustomAnalyzer': 'CustomAnalyzer',
            '#Microsoft.Azure.Search.PatternAnalyzer': 'PatternAnalyzer',
            '#Microsoft.Azure.Search.StandardAnalyzer': 'LuceneStandardAnalyzer',
            '#Microsoft.Azure.Search.StopAnalyzer': 'StopAnalyzer'
        }
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LexicalAnalyzer, self).__init__(**kwargs)
        self.odata_type = None  # type: Optional[str]
        self.name = kwargs['name']


class RequestOptions(msrest.serialization.Model):
    """Parameter group.

    :param x_ms_client_request_id: The tracking ID sent with the request to help with debugging.
    :type x_ms_client_request_id: str
    """

    _attribute_map = {
        'x_ms_client_request_id': {'key': 'x-ms-client-request-id', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RequestOptions, self).__init__(**kwargs)
        self.x_ms_client_request_id = kwargs.get('x_ms_client_request_id', None)


class ScoringProfile(msrest.serialization.Model):
    """Defines parameters for a search index that influence scoring in search queries.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the scoring profile.
    :type name: str
    :param text_weights: Parameters that boost scoring based on text matches in certain index
     fields.
    :type text_weights: ~azure.search.documents.indexes.models.TextWeights
    :param functions: The collection of functions that influence the scoring of documents.
    :type functions: list[~azure.search.documents.indexes.models.ScoringFunction]
    :param function_aggregation: A value indicating how the results of individual scoring functions
     should be combined. Defaults to "Sum". Ignored if there are no scoring functions. Possible
     values include: "sum", "average", "minimum", "maximum", "firstMatching".
    :type function_aggregation: str or
     ~azure.search.documents.indexes.models.ScoringFunctionAggregation
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'text_weights': {'key': 'text', 'type': 'TextWeights'},
        'functions': {'key': 'functions', 'type': '[ScoringFunction]'},
        'function_aggregation': {'key': 'functionAggregation', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ScoringProfile, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.text_weights = kwargs.get('text_weights', None)
        self.functions = kwargs.get('functions', None)
        self.function_aggregation = kwargs.get('function_aggregation', None)


class SearchError(msrest.serialization.Model):
    """Describes an error condition for the Azure Cognitive Search API.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar code: One of a server-defined set of error codes.
    :vartype code: str
    :ivar message: Required. A human-readable representation of the error.
    :vartype message: str
    :ivar details: An array of details about specific errors that led to this reported error.
    :vartype details: list[~azure.search.documents.indexes.models.SearchError]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'required': True, 'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '[SearchError]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SearchError, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.details = None


class SearchField(msrest.serialization.Model):
    # pylint: disable=too-many-instance-attributes
    """Represents a field in an index definition, which describes the name, data type, and search behavior of a field.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the field, which must be unique within the fields collection
     of the index or parent field.
    :type name: str
    :param type: Required. The data type of the field. Possible values include: "Edm.String",
     "Edm.Int32", "Edm.Int64", "Edm.Double", "Edm.Boolean", "Edm.DateTimeOffset",
     "Edm.GeographyPoint", "Edm.ComplexType".
    :type type: str or ~azure.search.documents.indexes.models.SearchFieldDataType
    :param key: A value indicating whether the field uniquely identifies documents in the index.
     Exactly one top-level field in each index must be chosen as the key field and it must be of
     type Edm.String. Key fields can be used to look up documents directly and update or delete
     specific documents. Default is false for simple fields and null for complex fields.
    :type key: bool
    :param retrievable: A value indicating whether the field can be returned in a search result.
     You can disable this option if you want to use a field (for example, margin) as a filter,
     sorting, or scoring mechanism but do not want the field to be visible to the end user. This
     property must be true for key fields, and it must be null for complex fields. This property can
     be changed on existing fields. Enabling this property does not cause any increase in index
     storage requirements. Default is true for simple fields and null for complex fields.
    :type retrievable: bool
    :param searchable: A value indicating whether the field is full-text searchable. This means it
     will undergo analysis such as word-breaking during indexing. If you set a searchable field to a
     value like "sunny day", internally it will be split into the individual tokens "sunny" and
     "day". This enables full-text searches for these terms. Fields of type Edm.String or
     Collection(Edm.String) are searchable by default. This property must be false for simple fields
     of other non-string data types, and it must be null for complex fields. Note: searchable fields
     consume extra space in your index since Azure Cognitive Search will store an additional
     tokenized version of the field value for full-text searches. If you want to save space in your
     index and you don't need a field to be included in searches, set searchable to false.
    :type searchable: bool
    :param filterable: A value indicating whether to enable the field to be referenced in $filter
     queries. filterable differs from searchable in how strings are handled. Fields of type
     Edm.String or Collection(Edm.String) that are filterable do not undergo word-breaking, so
     comparisons are for exact matches only. For example, if you set such a field f to "sunny day",
     $filter=f eq 'sunny' will find no matches, but $filter=f eq 'sunny day' will. This property
     must be null for complex fields. Default is true for simple fields and null for complex fields.
    :type filterable: bool
    :param sortable: A value indicating whether to enable the field to be referenced in $orderby
     expressions. By default Azure Cognitive Search sorts results by score, but in many experiences
     users will want to sort by fields in the documents. A simple field can be sortable only if it
     is single-valued (it has a single value in the scope of the parent document). Simple collection
     fields cannot be sortable, since they are multi-valued. Simple sub-fields of complex
     collections are also multi-valued, and therefore cannot be sortable. This is true whether it's
     an immediate parent field, or an ancestor field, that's the complex collection. Complex fields
     cannot be sortable and the sortable property must be null for such fields. The default for
     sortable is true for single-valued simple fields, false for multi-valued simple fields, and
     null for complex fields.
    :type sortable: bool
    :param facetable: A value indicating whether to enable the field to be referenced in facet
     queries. Typically used in a presentation of search results that includes hit count by category
     (for example, search for digital cameras and see hits by brand, by megapixels, by price, and so
     on). This property must be null for complex fields. Fields of type Edm.GeographyPoint or
     Collection(Edm.GeographyPoint) cannot be facetable. Default is true for all other simple
     fields.
    :type facetable: bool
    :param analyzer: The name of the analyzer to use for the field. This option can be used only
     with searchable fields and it can't be set together with either searchAnalyzer or
     indexAnalyzer. Once the analyzer is chosen, it cannot be changed for the field. Must be null
     for complex fields. Possible values include: "ar.microsoft", "ar.lucene", "hy.lucene",
     "bn.microsoft", "eu.lucene", "bg.microsoft", "bg.lucene", "ca.microsoft", "ca.lucene", "zh-
     Hans.microsoft", "zh-Hans.lucene", "zh-Hant.microsoft", "zh-Hant.lucene", "hr.microsoft",
     "cs.microsoft", "cs.lucene", "da.microsoft", "da.lucene", "nl.microsoft", "nl.lucene",
     "en.microsoft", "en.lucene", "et.microsoft", "fi.microsoft", "fi.lucene", "fr.microsoft",
     "fr.lucene", "gl.lucene", "de.microsoft", "de.lucene", "el.microsoft", "el.lucene",
     "gu.microsoft", "he.microsoft", "hi.microsoft", "hi.lucene", "hu.microsoft", "hu.lucene",
     "is.microsoft", "id.microsoft", "id.lucene", "ga.lucene", "it.microsoft", "it.lucene",
     "ja.microsoft", "ja.lucene", "kn.microsoft", "ko.microsoft", "ko.lucene", "lv.microsoft",
     "lv.lucene", "lt.microsoft", "ml.microsoft", "ms.microsoft", "mr.microsoft", "nb.microsoft",
     "no.lucene", "fa.lucene", "pl.microsoft", "pl.lucene", "pt-BR.microsoft", "pt-BR.lucene", "pt-
     PT.microsoft", "pt-PT.lucene", "pa.microsoft", "ro.microsoft", "ro.lucene", "ru.microsoft",
     "ru.lucene", "sr-cyrillic.microsoft", "sr-latin.microsoft", "sk.microsoft", "sl.microsoft",
     "es.microsoft", "es.lucene", "sv.microsoft", "sv.lucene", "ta.microsoft", "te.microsoft",
     "th.microsoft", "th.lucene", "tr.microsoft", "tr.lucene", "uk.microsoft", "ur.microsoft",
     "vi.microsoft", "standard.lucene", "standardasciifolding.lucene", "keyword", "pattern",
     "simple", "stop", "whitespace".
    :type analyzer: str or ~azure.search.documents.indexes.models.LexicalAnalyzerName
    :param search_analyzer: The name of the analyzer used at search time for the field. This option
     can be used only with searchable fields. It must be set together with indexAnalyzer and it
     cannot be set together with the analyzer option. This property cannot be set to the name of a
     language analyzer; use the analyzer property instead if you need a language analyzer. This
     analyzer can be updated on an existing field. Must be null for complex fields. Possible values
     include: "ar.microsoft", "ar.lucene", "hy.lucene", "bn.microsoft", "eu.lucene", "bg.microsoft",
     "bg.lucene", "ca.microsoft", "ca.lucene", "zh-Hans.microsoft", "zh-Hans.lucene", "zh-
     Hant.microsoft", "zh-Hant.lucene", "hr.microsoft", "cs.microsoft", "cs.lucene", "da.microsoft",
     "da.lucene", "nl.microsoft", "nl.lucene", "en.microsoft", "en.lucene", "et.microsoft",
     "fi.microsoft", "fi.lucene", "fr.microsoft", "fr.lucene", "gl.lucene", "de.microsoft",
     "de.lucene", "el.microsoft", "el.lucene", "gu.microsoft", "he.microsoft", "hi.microsoft",
     "hi.lucene", "hu.microsoft", "hu.lucene", "is.microsoft", "id.microsoft", "id.lucene",
     "ga.lucene", "it.microsoft", "it.lucene", "ja.microsoft", "ja.lucene", "kn.microsoft",
     "ko.microsoft", "ko.lucene", "lv.microsoft", "lv.lucene", "lt.microsoft", "ml.microsoft",
     "ms.microsoft", "mr.microsoft", "nb.microsoft", "no.lucene", "fa.lucene", "pl.microsoft",
     "pl.lucene", "pt-BR.microsoft", "pt-BR.lucene", "pt-PT.microsoft", "pt-PT.lucene",
     "pa.microsoft", "ro.microsoft", "ro.lucene", "ru.microsoft", "ru.lucene", "sr-
     cyrillic.microsoft", "sr-latin.microsoft", "sk.microsoft", "sl.microsoft", "es.microsoft",
     "es.lucene", "sv.microsoft", "sv.lucene", "ta.microsoft", "te.microsoft", "th.microsoft",
     "th.lucene", "tr.microsoft", "tr.lucene", "uk.microsoft", "ur.microsoft", "vi.microsoft",
     "standard.lucene", "standardasciifolding.lucene", "keyword", "pattern", "simple", "stop",
     "whitespace".
    :type search_analyzer: str or ~azure.search.documents.indexes.models.LexicalAnalyzerName
    :param index_analyzer: The name of the analyzer used at indexing time for the field. This
     option can be used only with searchable fields. It must be set together with searchAnalyzer and
     it cannot be set together with the analyzer option.  This property cannot be set to the name of
     a language analyzer; use the analyzer property instead if you need a language analyzer. Once
     the analyzer is chosen, it cannot be changed for the field. Must be null for complex fields.
     Possible values include: "ar.microsoft", "ar.lucene", "hy.lucene", "bn.microsoft", "eu.lucene",
     "bg.microsoft", "bg.lucene", "ca.microsoft", "ca.lucene", "zh-Hans.microsoft", "zh-
     Hans.lucene", "zh-Hant.microsoft", "zh-Hant.lucene", "hr.microsoft", "cs.microsoft",
     "cs.lucene", "da.microsoft", "da.lucene", "nl.microsoft", "nl.lucene", "en.microsoft",
     "en.lucene", "et.microsoft", "fi.microsoft", "fi.lucene", "fr.microsoft", "fr.lucene",
     "gl.lucene", "de.microsoft", "de.lucene", "el.microsoft", "el.lucene", "gu.microsoft",
     "he.microsoft", "hi.microsoft", "hi.lucene", "hu.microsoft", "hu.lucene", "is.microsoft",
     "id.microsoft", "id.lucene", "ga.lucene", "it.microsoft", "it.lucene", "ja.microsoft",
     "ja.lucene", "kn.microsoft", "ko.microsoft", "ko.lucene", "lv.microsoft", "lv.lucene",
     "lt.microsoft", "ml.microsoft", "ms.microsoft", "mr.microsoft", "nb.microsoft", "no.lucene",
     "fa.lucene", "pl.microsoft", "pl.lucene", "pt-BR.microsoft", "pt-BR.lucene", "pt-PT.microsoft",
     "pt-PT.lucene", "pa.microsoft", "ro.microsoft", "ro.lucene", "ru.microsoft", "ru.lucene", "sr-
     cyrillic.microsoft", "sr-latin.microsoft", "sk.microsoft", "sl.microsoft", "es.microsoft",
     "es.lucene", "sv.microsoft", "sv.lucene", "ta.microsoft", "te.microsoft", "th.microsoft",
     "th.lucene", "tr.microsoft", "tr.lucene", "uk.microsoft", "ur.microsoft", "vi.microsoft",
     "standard.lucene", "standardasciifolding.lucene", "keyword", "pattern", "simple", "stop",
     "whitespace".
    :type index_analyzer: str or ~azure.search.documents.indexes.models.LexicalAnalyzerName
    :param synonym_maps: A list of the names of synonym maps to associate with this field. This
     option can be used only with searchable fields. Currently only one synonym map per field is
     supported. Assigning a synonym map to a field ensures that query terms targeting that field are
     expanded at query-time using the rules in the synonym map. This attribute can be changed on
     existing fields. Must be null or an empty collection for complex fields.
    :type synonym_maps: list[str]
    :param fields: A list of sub-fields if this is a field of type Edm.ComplexType or
     Collection(Edm.ComplexType). Must be null or empty for simple fields.
    :type fields: list[~azure.search.documents.indexes.models.SearchField]
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'key': {'key': 'key', 'type': 'bool'},
        'retrievable': {'key': 'retrievable', 'type': 'bool'},
        'searchable': {'key': 'searchable', 'type': 'bool'},
        'filterable': {'key': 'filterable', 'type': 'bool'},
        'sortable': {'key': 'sortable', 'type': 'bool'},
        'facetable': {'key': 'facetable', 'type': 'bool'},
        'analyzer': {'key': 'analyzer', 'type': 'str'},
        'search_analyzer': {'key': 'searchAnalyzer', 'type': 'str'},
        'index_analyzer': {'key': 'indexAnalyzer', 'type': 'str'},
        'synonym_maps': {'key': 'synonymMaps', 'type': '[str]'},
        'fields': {'key': 'fields', 'type': '[SearchField]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SearchField, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.type = kwargs['type']
        self.key = kwargs.get('key', None)
        self.retrievable = kwargs.get('retrievable', None)
        self.searchable = kwargs.get('searchable', None)
        self.filterable = kwargs.get('filterable', None)
        self.sortable = kwargs.get('sortable', None)
        self.facetable = kwargs.get('facetable', None)
        self.analyzer = kwargs.get('analyzer', None)
        self.search_analyzer = kwargs.get('search_analyzer', None)
        self.index_analyzer = kwargs.get('index_analyzer', None)
        self.synonym_maps = kwargs.get('synonym_maps', None)
        self.fields = kwargs.get('fields', None)


class SearchIndex(msrest.serialization.Model):
    # pylint: disable=too-many-instance-attributes
    """Represents a search index definition, which describes the fields and search behavior of an index.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the index.
    :type name: str
    :param fields: Required. The fields of the index.
    :type fields: list[~azure.search.documents.indexes.models.SearchField]
    :param scoring_profiles: The scoring profiles for the index.
    :type scoring_profiles: list[~azure.search.documents.indexes.models.ScoringProfile]
    :param default_scoring_profile: The name of the scoring profile to use if none is specified in
     the query. If this property is not set and no scoring profile is specified in the query, then
     default scoring (tf-idf) will be used.
    :type default_scoring_profile: str
    :param cors_options: Options to control Cross-Origin Resource Sharing (CORS) for the index.
    :type cors_options: ~azure.search.documents.indexes.models.CorsOptions
    :param suggesters: The suggesters for the index.
    :type suggesters: list[~azure.search.documents.indexes.models.Suggester]
    :param analyzers: The analyzers for the index.
    :type analyzers: list[~azure.search.documents.indexes.models.LexicalAnalyzer]
    :param tokenizers: The tokenizers for the index.
    :type tokenizers: list[~azure.search.documents.indexes.models.LexicalTokenizer]
    :param token_filters: The token filters for the index.
    :type token_filters: list[~azure.search.documents.indexes.models.TokenFilter]
    :param char_filters: The character filters for the index.
    :type char_filters: list[~azure.search.documents.indexes.models.CharFilter]
    :param encryption_key: A description of an encryption key that you create in Azure Key Vault.
     This key is used to provide an additional level of encryption-at-rest for your data when you
     want full assurance that no one, not even Microsoft, can decrypt your data in Azure Cognitive
     Search. Once you have encrypted your data, it will always remain encrypted. Azure Cognitive
     Search will ignore attempts to set this property to null. You can change this property as
     needed if you want to rotate your encryption key; Your data will be unaffected. Encryption with
     customer-managed keys is not available for free search services, and is only available for paid
     services created on or after January 1, 2019.
    :type encryption_key: ~azure.search.documents.indexes.models.SearchResourceEncryptionKey
    :param similarity: The type of similarity algorithm to be used when scoring and ranking the
     documents matching a search query. The similarity algorithm can only be defined at index
     creation time and cannot be modified on existing indexes. If null, the ClassicSimilarity
     algorithm is used.
    :type similarity: ~azure.search.documents.indexes.models.Similarity
    :param e_tag: The ETag of the index.
    :type e_tag: str
    """

    _validation = {
        'name': {'required': True},
        'fields': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'fields': {'key': 'fields', 'type': '[SearchField]'},
        'scoring_profiles': {'key': 'scoringProfiles', 'type': '[ScoringProfile]'},
        'default_scoring_profile': {'key': 'defaultScoringProfile', 'type': 'str'},
        'cors_options': {'key': 'corsOptions', 'type': 'CorsOptions'},
        'suggesters': {'key': 'suggesters', 'type': '[Suggester]'},
        'analyzers': {'key': 'analyzers', 'type': '[LexicalAnalyzer]'},
        'tokenizers': {'key': 'tokenizers', 'type': '[LexicalTokenizer]'},
        'token_filters': {'key': 'tokenFilters', 'type': '[TokenFilter]'},
        'char_filters': {'key': 'charFilters', 'type': '[CharFilter]'},
        'encryption_key': {'key': 'encryptionKey', 'type': 'SearchResourceEncryptionKey'},
        'similarity': {'key': 'similarity', 'type': 'Similarity'},
        'e_tag': {'key': '@odata\\.etag', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SearchIndex, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.fields = kwargs['fields']
        self.scoring_profiles = kwargs.get('scoring_profiles', None)
        self.default_scoring_profile = kwargs.get('default_scoring_profile', None)
        self.cors_options = kwargs.get('cors_options', None)
        self.suggesters = kwargs.get('suggesters', None)
        self.analyzers = kwargs.get('analyzers', None)
        self.tokenizers = kwargs.get('tokenizers', None)
        self.token_filters = kwargs.get('token_filters', None)
        self.char_filters = kwargs.get('char_filters', None)
        self.encryption_key = kwargs.get('encryption_key', None)
        self.similarity = kwargs.get('similarity', None)
        self.e_tag = kwargs.get('e_tag', None)
