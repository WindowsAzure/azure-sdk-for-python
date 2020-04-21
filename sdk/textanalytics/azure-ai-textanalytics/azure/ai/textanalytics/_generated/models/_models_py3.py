# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class DetectedLanguage(msrest.serialization.Model):
    """DetectedLanguage.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Long name of a detected language (e.g. English, French).
    :type name: str
    :param iso6391_name: Required. A two letter representation of the detected language according
     to the ISO 639-1 standard (e.g. en, fr).
    :type iso6391_name: str
    :param score: Required. A confidence score between 0 and 1. Scores close to 1 indicate 100%
     certainty that the identified language is true.
    :type score: float
    """

    _validation = {
        'name': {'required': True},
        'iso6391_name': {'required': True},
        'score': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'iso6391_name': {'key': 'iso6391Name', 'type': 'str'},
        'score': {'key': 'score', 'type': 'float'},
    }

    def __init__(
        self,
        *,
        name: str,
        iso6391_name: str,
        score: float,
        **kwargs
    ):
        super(DetectedLanguage, self).__init__(**kwargs)
        self.name = name
        self.iso6391_name = iso6391_name
        self.score = score


class DocumentEntities(msrest.serialization.Model):
    """DocumentEntities.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param entities: Required. Recognized entities in the document.
    :type entities: list[~azure.ai.textanalytics.models.Entity]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the document payload.
    :type statistics: ~azure.ai.textanalytics.models.DocumentStatistics
    """

    _validation = {
        'id': {'required': True},
        'entities': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'entities': {'key': 'entities', 'type': '[Entity]'},
        'statistics': {'key': 'statistics', 'type': 'DocumentStatistics'},
    }

    def __init__(
        self,
        *,
        id: str,
        entities: List["Entity"],
        statistics: Optional["DocumentStatistics"] = None,
        **kwargs
    ):
        super(DocumentEntities, self).__init__(**kwargs)
        self.id = id
        self.entities = entities
        self.statistics = statistics


class DocumentError(msrest.serialization.Model):
    """DocumentError.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Document Id.
    :type id: str
    :param error: Required. Document Error.
    :type error: ~azure.ai.textanalytics.models.TextAnalyticsError
    """

    _validation = {
        'id': {'required': True},
        'error': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'error': {'key': 'error', 'type': 'TextAnalyticsError'},
    }

    def __init__(
        self,
        *,
        id: str,
        error: "TextAnalyticsError",
        **kwargs
    ):
        super(DocumentError, self).__init__(**kwargs)
        self.id = id
        self.error = error


class DocumentKeyPhrases(msrest.serialization.Model):
    """DocumentKeyPhrases.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param key_phrases: Required. A list of representative words or phrases. The number of key
     phrases returned is proportional to the number of words in the input document.
    :type key_phrases: list[str]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the document payload.
    :type statistics: ~azure.ai.textanalytics.models.DocumentStatistics
    """

    _validation = {
        'id': {'required': True},
        'key_phrases': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'key_phrases': {'key': 'keyPhrases', 'type': '[str]'},
        'statistics': {'key': 'statistics', 'type': 'DocumentStatistics'},
    }

    def __init__(
        self,
        *,
        id: str,
        key_phrases: List[str],
        statistics: Optional["DocumentStatistics"] = None,
        **kwargs
    ):
        super(DocumentKeyPhrases, self).__init__(**kwargs)
        self.id = id
        self.key_phrases = key_phrases
        self.statistics = statistics


class DocumentLanguage(msrest.serialization.Model):
    """DocumentLanguage.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param detected_languages: Required. A list of extracted languages.
    :type detected_languages: list[~azure.ai.textanalytics.models.DetectedLanguage]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the document payload.
    :type statistics: ~azure.ai.textanalytics.models.DocumentStatistics
    """

    _validation = {
        'id': {'required': True},
        'detected_languages': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'detected_languages': {'key': 'detectedLanguages', 'type': '[DetectedLanguage]'},
        'statistics': {'key': 'statistics', 'type': 'DocumentStatistics'},
    }

    def __init__(
        self,
        *,
        id: str,
        detected_languages: List["DetectedLanguage"],
        statistics: Optional["DocumentStatistics"] = None,
        **kwargs
    ):
        super(DocumentLanguage, self).__init__(**kwargs)
        self.id = id
        self.detected_languages = detected_languages
        self.statistics = statistics


class DocumentLinkedEntities(msrest.serialization.Model):
    """DocumentLinkedEntities.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param entities: Required. Recognized well-known entities in the document.
    :type entities: list[~azure.ai.textanalytics.models.LinkedEntity]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the document payload.
    :type statistics: ~azure.ai.textanalytics.models.DocumentStatistics
    """

    _validation = {
        'id': {'required': True},
        'entities': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'entities': {'key': 'entities', 'type': '[LinkedEntity]'},
        'statistics': {'key': 'statistics', 'type': 'DocumentStatistics'},
    }

    def __init__(
        self,
        *,
        id: str,
        entities: List["LinkedEntity"],
        statistics: Optional["DocumentStatistics"] = None,
        **kwargs
    ):
        super(DocumentLinkedEntities, self).__init__(**kwargs)
        self.id = id
        self.entities = entities
        self.statistics = statistics


class DocumentSentiment(msrest.serialization.Model):
    """DocumentSentiment.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param sentiment: Required. Predicted sentiment for document (Negative, Neutral, Positive, or
     Mixed). Possible values include: "positive", "neutral", "negative", "mixed".
    :type sentiment: str or ~azure.ai.textanalytics.models.DocumentSentimentValue
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the document payload.
    :type statistics: ~azure.ai.textanalytics.models.DocumentStatistics
    :param document_scores: Required. Document level sentiment confidence scores between 0 and 1
     for each sentiment class.
    :type document_scores: ~azure.ai.textanalytics.models.SentimentConfidenceScorePerLabel
    :param sentences: Required. Sentence level sentiment analysis.
    :type sentences: list[~azure.ai.textanalytics.models.SentenceSentiment]
    """

    _validation = {
        'id': {'required': True},
        'sentiment': {'required': True},
        'document_scores': {'required': True},
        'sentences': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'sentiment': {'key': 'sentiment', 'type': 'str'},
        'statistics': {'key': 'statistics', 'type': 'DocumentStatistics'},
        'document_scores': {'key': 'documentScores', 'type': 'SentimentConfidenceScorePerLabel'},
        'sentences': {'key': 'sentences', 'type': '[SentenceSentiment]'},
    }

    def __init__(
        self,
        *,
        id: str,
        sentiment: Union[str, "DocumentSentimentValue"],
        document_scores: "SentimentConfidenceScorePerLabel",
        sentences: List["SentenceSentiment"],
        statistics: Optional["DocumentStatistics"] = None,
        **kwargs
    ):
        super(DocumentSentiment, self).__init__(**kwargs)
        self.id = id
        self.sentiment = sentiment
        self.statistics = statistics
        self.document_scores = document_scores
        self.sentences = sentences


class DocumentStatistics(msrest.serialization.Model):
    """if showStats=true was specified in the request this field will contain information about the document payload.

    All required parameters must be populated in order to send to Azure.

    :param characters_count: Required. Number of text elements recognized in the document.
    :type characters_count: int
    :param transactions_count: Required. Number of transactions for the document.
    :type transactions_count: int
    """

    _validation = {
        'characters_count': {'required': True},
        'transactions_count': {'required': True},
    }

    _attribute_map = {
        'characters_count': {'key': 'charactersCount', 'type': 'int'},
        'transactions_count': {'key': 'transactionsCount', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        characters_count: int,
        transactions_count: int,
        **kwargs
    ):
        super(DocumentStatistics, self).__init__(**kwargs)
        self.characters_count = characters_count
        self.transactions_count = transactions_count


class EntitiesResult(msrest.serialization.Model):
    """EntitiesResult.

    All required parameters must be populated in order to send to Azure.

    :param documents: Required. Response by document.
    :type documents: list[~azure.ai.textanalytics.models.DocumentEntities]
    :param errors: Required. Errors by document id.
    :type errors: list[~azure.ai.textanalytics.models.DocumentError]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the request payload.
    :type statistics: ~azure.ai.textanalytics.models.RequestStatistics
    :param model_version: Required. This field indicates which model is used for scoring.
    :type model_version: str
    """

    _validation = {
        'documents': {'required': True},
        'errors': {'required': True},
        'model_version': {'required': True},
    }

    _attribute_map = {
        'documents': {'key': 'documents', 'type': '[DocumentEntities]'},
        'errors': {'key': 'errors', 'type': '[DocumentError]'},
        'statistics': {'key': 'statistics', 'type': 'RequestStatistics'},
        'model_version': {'key': 'modelVersion', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        documents: List["DocumentEntities"],
        errors: List["DocumentError"],
        model_version: str,
        statistics: Optional["RequestStatistics"] = None,
        **kwargs
    ):
        super(EntitiesResult, self).__init__(**kwargs)
        self.documents = documents
        self.errors = errors
        self.statistics = statistics
        self.model_version = model_version


class Entity(msrest.serialization.Model):
    """Entity.

    All required parameters must be populated in order to send to Azure.

    :param text: Required. Entity text as appears in the request.
    :type text: str
    :param type: Required. Entity type, such as Person/Location/Org/SSN etc.
    :type type: str
    :param subtype: Entity sub type, such as Age/Year/TimeRange etc.
    :type subtype: str
    :param offset: Required. Start position (in Unicode characters) for the entity text.
    :type offset: int
    :param length: Required. Length (in Unicode characters) for the entity text.
    :type length: int
    :param score: Required. Confidence score between 0 and 1 of the extracted entity.
    :type score: float
    """

    _validation = {
        'text': {'required': True},
        'type': {'required': True},
        'offset': {'required': True},
        'length': {'required': True},
        'score': {'required': True},
    }

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'subtype': {'key': 'subtype', 'type': 'str'},
        'offset': {'key': 'offset', 'type': 'int'},
        'length': {'key': 'length', 'type': 'int'},
        'score': {'key': 'score', 'type': 'float'},
    }

    def __init__(
        self,
        *,
        text: str,
        type: str,
        offset: int,
        length: int,
        score: float,
        subtype: Optional[str] = None,
        **kwargs
    ):
        super(Entity, self).__init__(**kwargs)
        self.text = text
        self.type = type
        self.subtype = subtype
        self.offset = offset
        self.length = length
        self.score = score


class EntityLinkingResult(msrest.serialization.Model):
    """EntityLinkingResult.

    All required parameters must be populated in order to send to Azure.

    :param documents: Required. Response by document.
    :type documents: list[~azure.ai.textanalytics.models.DocumentLinkedEntities]
    :param errors: Required. Errors by document id.
    :type errors: list[~azure.ai.textanalytics.models.DocumentError]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the request payload.
    :type statistics: ~azure.ai.textanalytics.models.RequestStatistics
    :param model_version: Required. This field indicates which model is used for scoring.
    :type model_version: str
    """

    _validation = {
        'documents': {'required': True},
        'errors': {'required': True},
        'model_version': {'required': True},
    }

    _attribute_map = {
        'documents': {'key': 'documents', 'type': '[DocumentLinkedEntities]'},
        'errors': {'key': 'errors', 'type': '[DocumentError]'},
        'statistics': {'key': 'statistics', 'type': 'RequestStatistics'},
        'model_version': {'key': 'modelVersion', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        documents: List["DocumentLinkedEntities"],
        errors: List["DocumentError"],
        model_version: str,
        statistics: Optional["RequestStatistics"] = None,
        **kwargs
    ):
        super(EntityLinkingResult, self).__init__(**kwargs)
        self.documents = documents
        self.errors = errors
        self.statistics = statistics
        self.model_version = model_version


class InnerError(msrest.serialization.Model):
    """InnerError.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. Error code. Possible values include: "invalidParameterValue",
     "invalidRequestBodyFormat", "emptyRequest", "missingInputRecords", "invalidDocument",
     "modelVersionIncorrect", "invalidDocumentBatch", "unsupportedLanguageCode",
     "invalidCountryHint".
    :type code: str or ~azure.ai.textanalytics.models.InnerErrorCodeValue
    :param message: Required. Error message.
    :type message: str
    :param details: Error details.
    :type details: dict[str, str]
    :param target: Error target.
    :type target: str
    :param inner_error: Inner error contains more specific information.
    :type inner_error: ~azure.ai.textanalytics.models.InnerError
    """

    _validation = {
        'code': {'required': True},
        'message': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '{str}'},
        'target': {'key': 'target', 'type': 'str'},
        'inner_error': {'key': 'innerError', 'type': 'InnerError'},
    }

    def __init__(
        self,
        *,
        code: Union[str, "InnerErrorCodeValue"],
        message: str,
        details: Optional[Dict[str, str]] = None,
        target: Optional[str] = None,
        inner_error: Optional["InnerError"] = None,
        **kwargs
    ):
        super(InnerError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.details = details
        self.target = target
        self.inner_error = inner_error


class KeyPhraseResult(msrest.serialization.Model):
    """KeyPhraseResult.

    All required parameters must be populated in order to send to Azure.

    :param documents: Required. Response by document.
    :type documents: list[~azure.ai.textanalytics.models.DocumentKeyPhrases]
    :param errors: Required. Errors by document id.
    :type errors: list[~azure.ai.textanalytics.models.DocumentError]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the request payload.
    :type statistics: ~azure.ai.textanalytics.models.RequestStatistics
    :param model_version: Required. This field indicates which model is used for scoring.
    :type model_version: str
    """

    _validation = {
        'documents': {'required': True},
        'errors': {'required': True},
        'model_version': {'required': True},
    }

    _attribute_map = {
        'documents': {'key': 'documents', 'type': '[DocumentKeyPhrases]'},
        'errors': {'key': 'errors', 'type': '[DocumentError]'},
        'statistics': {'key': 'statistics', 'type': 'RequestStatistics'},
        'model_version': {'key': 'modelVersion', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        documents: List["DocumentKeyPhrases"],
        errors: List["DocumentError"],
        model_version: str,
        statistics: Optional["RequestStatistics"] = None,
        **kwargs
    ):
        super(KeyPhraseResult, self).__init__(**kwargs)
        self.documents = documents
        self.errors = errors
        self.statistics = statistics
        self.model_version = model_version


class LanguageBatchInput(msrest.serialization.Model):
    """LanguageBatchInput.

    All required parameters must be populated in order to send to Azure.

    :param documents: Required.
    :type documents: list[~azure.ai.textanalytics.models.LanguageInput]
    """

    _validation = {
        'documents': {'required': True},
    }

    _attribute_map = {
        'documents': {'key': 'documents', 'type': '[LanguageInput]'},
    }

    def __init__(
        self,
        *,
        documents: List["LanguageInput"],
        **kwargs
    ):
        super(LanguageBatchInput, self).__init__(**kwargs)
        self.documents = documents


class LanguageInput(msrest.serialization.Model):
    """LanguageInput.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param text: Required.
    :type text: str
    :param country_hint:
    :type country_hint: str
    """

    _validation = {
        'id': {'required': True},
        'text': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'text': {'key': 'text', 'type': 'str'},
        'country_hint': {'key': 'countryHint', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: str,
        text: str,
        country_hint: Optional[str] = None,
        **kwargs
    ):
        super(LanguageInput, self).__init__(**kwargs)
        self.id = id
        self.text = text
        self.country_hint = country_hint


class LanguageResult(msrest.serialization.Model):
    """LanguageResult.

    All required parameters must be populated in order to send to Azure.

    :param documents: Required. Response by document.
    :type documents: list[~azure.ai.textanalytics.models.DocumentLanguage]
    :param errors: Required. Errors by document id.
    :type errors: list[~azure.ai.textanalytics.models.DocumentError]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the request payload.
    :type statistics: ~azure.ai.textanalytics.models.RequestStatistics
    :param model_version: Required. This field indicates which model is used for scoring.
    :type model_version: str
    """

    _validation = {
        'documents': {'required': True},
        'errors': {'required': True},
        'model_version': {'required': True},
    }

    _attribute_map = {
        'documents': {'key': 'documents', 'type': '[DocumentLanguage]'},
        'errors': {'key': 'errors', 'type': '[DocumentError]'},
        'statistics': {'key': 'statistics', 'type': 'RequestStatistics'},
        'model_version': {'key': 'modelVersion', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        documents: List["DocumentLanguage"],
        errors: List["DocumentError"],
        model_version: str,
        statistics: Optional["RequestStatistics"] = None,
        **kwargs
    ):
        super(LanguageResult, self).__init__(**kwargs)
        self.documents = documents
        self.errors = errors
        self.statistics = statistics
        self.model_version = model_version


class LinkedEntity(msrest.serialization.Model):
    """LinkedEntity.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Entity Linking formal name.
    :type name: str
    :param matches: Required. List of instances this entity appears in the text.
    :type matches: list[~azure.ai.textanalytics.models.Match]
    :param language: Required. Language used in the data source.
    :type language: str
    :param id: Unique identifier of the recognized entity from the data source.
    :type id: str
    :param url: Required. URL for the entity's page from the data source.
    :type url: str
    :param data_source: Required. Data source used to extract entity linking, such as Wiki/Bing
     etc.
    :type data_source: str
    """

    _validation = {
        'name': {'required': True},
        'matches': {'required': True},
        'language': {'required': True},
        'url': {'required': True},
        'data_source': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'matches': {'key': 'matches', 'type': '[Match]'},
        'language': {'key': 'language', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'data_source': {'key': 'dataSource', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: str,
        matches: List["Match"],
        language: str,
        url: str,
        data_source: str,
        id: Optional[str] = None,
        **kwargs
    ):
        super(LinkedEntity, self).__init__(**kwargs)
        self.name = name
        self.matches = matches
        self.language = language
        self.id = id
        self.url = url
        self.data_source = data_source


class Match(msrest.serialization.Model):
    """Match.

    All required parameters must be populated in order to send to Azure.

    :param score: Required. If a well-known item is recognized, a decimal number denoting the
     confidence level between 0 and 1 will be returned.
    :type score: float
    :param text: Required. Entity text as appears in the request.
    :type text: str
    :param offset: Required. Start position (in Unicode characters) for the entity match text.
    :type offset: int
    :param length: Required. Length (in Unicode characters) for the entity match text.
    :type length: int
    """

    _validation = {
        'score': {'required': True},
        'text': {'required': True},
        'offset': {'required': True},
        'length': {'required': True},
    }

    _attribute_map = {
        'score': {'key': 'score', 'type': 'float'},
        'text': {'key': 'text', 'type': 'str'},
        'offset': {'key': 'offset', 'type': 'int'},
        'length': {'key': 'length', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        score: float,
        text: str,
        offset: int,
        length: int,
        **kwargs
    ):
        super(Match, self).__init__(**kwargs)
        self.score = score
        self.text = text
        self.offset = offset
        self.length = length


class MultiLanguageBatchInput(msrest.serialization.Model):
    """Contains a set of input documents to be analyzed by the service.

    All required parameters must be populated in order to send to Azure.

    :param documents: Required. The set of documents to process as part of this batch.
    :type documents: list[~azure.ai.textanalytics.models.MultiLanguageInput]
    """

    _validation = {
        'documents': {'required': True},
    }

    _attribute_map = {
        'documents': {'key': 'documents', 'type': '[MultiLanguageInput]'},
    }

    def __init__(
        self,
        *,
        documents: List["MultiLanguageInput"],
        **kwargs
    ):
        super(MultiLanguageBatchInput, self).__init__(**kwargs)
        self.documents = documents


class MultiLanguageInput(msrest.serialization.Model):
    """Contains an input document to be analyzed by the service.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. A unique, non-empty document identifier.
    :type id: str
    :param text: Required. The input text to process.
    :type text: str
    :param language: (Optional) This is the 2 letter ISO 639-1 representation of a language. For
     example, use "en" for English; "es" for Spanish etc. If not set, use "en" for English as
     default.
    :type language: str
    """

    _validation = {
        'id': {'required': True},
        'text': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'text': {'key': 'text', 'type': 'str'},
        'language': {'key': 'language', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: str,
        text: str,
        language: Optional[str] = None,
        **kwargs
    ):
        super(MultiLanguageInput, self).__init__(**kwargs)
        self.id = id
        self.text = text
        self.language = language


class RequestStatistics(msrest.serialization.Model):
    """if showStats=true was specified in the request this field will contain information about the request payload.

    All required parameters must be populated in order to send to Azure.

    :param documents_count: Required. Number of documents submitted in the request.
    :type documents_count: int
    :param valid_documents_count: Required. Number of valid documents. This excludes empty, over-
     size limit or non-supported languages documents.
    :type valid_documents_count: int
    :param erroneous_documents_count: Required. Number of invalid documents. This includes empty,
     over-size limit or non-supported languages documents.
    :type erroneous_documents_count: int
    :param transactions_count: Required. Number of transactions for the request.
    :type transactions_count: long
    """

    _validation = {
        'documents_count': {'required': True},
        'valid_documents_count': {'required': True},
        'erroneous_documents_count': {'required': True},
        'transactions_count': {'required': True},
    }

    _attribute_map = {
        'documents_count': {'key': 'documentsCount', 'type': 'int'},
        'valid_documents_count': {'key': 'validDocumentsCount', 'type': 'int'},
        'erroneous_documents_count': {'key': 'erroneousDocumentsCount', 'type': 'int'},
        'transactions_count': {'key': 'transactionsCount', 'type': 'long'},
    }

    def __init__(
        self,
        *,
        documents_count: int,
        valid_documents_count: int,
        erroneous_documents_count: int,
        transactions_count: int,
        **kwargs
    ):
        super(RequestStatistics, self).__init__(**kwargs)
        self.documents_count = documents_count
        self.valid_documents_count = valid_documents_count
        self.erroneous_documents_count = erroneous_documents_count
        self.transactions_count = transactions_count


class SentenceSentiment(msrest.serialization.Model):
    """SentenceSentiment.

    All required parameters must be populated in order to send to Azure.

    :param sentiment: Required. The predicted Sentiment for the sentence. Possible values include:
     "positive", "neutral", "negative".
    :type sentiment: str or ~azure.ai.textanalytics.models.SentenceSentimentValue
    :param sentence_scores: Required. The sentiment confidence score between 0 and 1 for the
     sentence for all classes.
    :type sentence_scores: ~azure.ai.textanalytics.models.SentimentConfidenceScorePerLabel
    :param offset: Required. The sentence offset from the start of the document.
    :type offset: int
    :param length: Required. The length of the sentence by Unicode standard.
    :type length: int
    :param warnings: The warnings generated for the sentence.
    :type warnings: list[str]
    """

    _validation = {
        'sentiment': {'required': True},
        'sentence_scores': {'required': True},
        'offset': {'required': True},
        'length': {'required': True},
    }

    _attribute_map = {
        'sentiment': {'key': 'sentiment', 'type': 'str'},
        'sentence_scores': {'key': 'sentenceScores', 'type': 'SentimentConfidenceScorePerLabel'},
        'offset': {'key': 'offset', 'type': 'int'},
        'length': {'key': 'length', 'type': 'int'},
        'warnings': {'key': 'warnings', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        sentiment: Union[str, "SentenceSentimentValue"],
        sentence_scores: "SentimentConfidenceScorePerLabel",
        offset: int,
        length: int,
        warnings: Optional[List[str]] = None,
        **kwargs
    ):
        super(SentenceSentiment, self).__init__(**kwargs)
        self.sentiment = sentiment
        self.sentence_scores = sentence_scores
        self.offset = offset
        self.length = length
        self.warnings = warnings


class SentimentConfidenceScorePerLabel(msrest.serialization.Model):
    """Represents the confidence scores between 0 and 1 across all sentiment classes: positive, neutral, negative.

    All required parameters must be populated in order to send to Azure.

    :param positive: Required.
    :type positive: float
    :param neutral: Required.
    :type neutral: float
    :param negative: Required.
    :type negative: float
    """

    _validation = {
        'positive': {'required': True},
        'neutral': {'required': True},
        'negative': {'required': True},
    }

    _attribute_map = {
        'positive': {'key': 'positive', 'type': 'float'},
        'neutral': {'key': 'neutral', 'type': 'float'},
        'negative': {'key': 'negative', 'type': 'float'},
    }

    def __init__(
        self,
        *,
        positive: float,
        neutral: float,
        negative: float,
        **kwargs
    ):
        super(SentimentConfidenceScorePerLabel, self).__init__(**kwargs)
        self.positive = positive
        self.neutral = neutral
        self.negative = negative


class SentimentResponse(msrest.serialization.Model):
    """SentimentResponse.

    All required parameters must be populated in order to send to Azure.

    :param documents: Required. Sentiment analysis per document.
    :type documents: list[~azure.ai.textanalytics.models.DocumentSentiment]
    :param errors: Required. Errors by document id.
    :type errors: list[~azure.ai.textanalytics.models.DocumentError]
    :param statistics: if showStats=true was specified in the request this field will contain
     information about the request payload.
    :type statistics: ~azure.ai.textanalytics.models.RequestStatistics
    :param model_version: Required. This field indicates which model is used for scoring.
    :type model_version: str
    """

    _validation = {
        'documents': {'required': True},
        'errors': {'required': True},
        'model_version': {'required': True},
    }

    _attribute_map = {
        'documents': {'key': 'documents', 'type': '[DocumentSentiment]'},
        'errors': {'key': 'errors', 'type': '[DocumentError]'},
        'statistics': {'key': 'statistics', 'type': 'RequestStatistics'},
        'model_version': {'key': 'modelVersion', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        documents: List["DocumentSentiment"],
        errors: List["DocumentError"],
        model_version: str,
        statistics: Optional["RequestStatistics"] = None,
        **kwargs
    ):
        super(SentimentResponse, self).__init__(**kwargs)
        self.documents = documents
        self.errors = errors
        self.statistics = statistics
        self.model_version = model_version


class TextAnalyticsError(msrest.serialization.Model):
    """TextAnalyticsError.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. Error code. Possible values include: "invalidRequest",
     "invalidArgument", "internalServerError", "serviceUnavailable".
    :type code: str or ~azure.ai.textanalytics.models.ErrorCodeValue
    :param message: Required. Error message.
    :type message: str
    :param target: Error target.
    :type target: str
    :param inner_error: Inner error contains more specific information.
    :type inner_error: ~azure.ai.textanalytics.models.InnerError
    :param details: Details about specific errors that led to this reported error.
    :type details: list[~azure.ai.textanalytics.models.TextAnalyticsError]
    """

    _validation = {
        'code': {'required': True},
        'message': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'inner_error': {'key': 'innerError', 'type': 'InnerError'},
        'details': {'key': 'details', 'type': '[TextAnalyticsError]'},
    }

    def __init__(
        self,
        *,
        code: Union[str, "ErrorCodeValue"],
        message: str,
        target: Optional[str] = None,
        inner_error: Optional["InnerError"] = None,
        details: Optional[List["TextAnalyticsError"]] = None,
        **kwargs
    ):
        super(TextAnalyticsError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.target = target
        self.inner_error = inner_error
        self.details = details
