

class DocumentEntities(object):
    """DocumentEntities.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param entities: Required. Recognized entities in the document.
    :type entities: list[~textanalytics.models.Entity]
    :param statistics: if showStats=true was specified in the request this
     field will contain information about the document payload.
    :type statistics: ~textanalytics.models.DocumentStatistics
    :param bool is_error: Boolean check for error item when iterating over list of
     results. Always False for an instance of a DocumentEntities.
    """

    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.entities = kwargs.get('entities', None)
        self.statistics = kwargs.get('statistics', None)
        self.is_error = False


class Entity(object):
    """Entity.

    All required parameters must be populated in order to send to Azure.

    :param text: Required. Entity text as appears in the request.
    :type text: str
    :param type: Required. Entity type, such as Person/Location/Org/SSN etc
    :type type: str
    :param sub_type: Entity sub type, such as Age/Year/TimeRange etc
    :type sub_type: str
    :param offset: Required. Start position (in Unicode characters) for the
     entity text.
    :type offset: int
    :param length: Required. Length (in Unicode characters) for the entity
     text.
    :type length: int
    :param score: Required. Confidence score between 0 and 1 of the extracted
     entity.
    :type score: float
    """

    def __init__(self, **kwargs):
        self.text = kwargs.get('text', None)
        self.type = kwargs.get('type', None)
        self.sub_type = kwargs.get('sub_type', None)
        self.offset = kwargs.get('offset', None)
        self.length = kwargs.get('length', None)
        self.score = kwargs.get('score', None)

    @classmethod
    def _from_generated(cls, entity):
        return cls(
            text=entity.text,
            type=entity.type,
            sub_type=entity.sub_type,
            offset=entity.offset,
            length=entity.length,
            score=entity.score
        )


class DocumentKeyPhrases(object):
    """DocumentKeyPhrases.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param key_phrases: Required. A list of representative words or phrases.
     The number of key phrases returned is proportional to the number of words
     in the input document.
    :type key_phrases: list[str]
    :param statistics: if showStats=true was specified in the request this
     field will contain information about the document payload.
    :type statistics: ~textanalytics.models.DocumentStatistics
    :param bool is_error: Boolean check for error item when iterating over list of
     results. Always False for an instance of a DocumentKeyPhrases.
    """
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.key_phrases = kwargs.get('key_phrases', None)
        self.statistics = kwargs.get('statistics', None)
        self.is_error = False


class DocumentLinkedEntities(object):
    """DocumentLinkedEntities.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param entities: Required. Recognized well-known entities in the document.
    :type entities: list[~textanalytics.models.LinkedEntity]
    :param statistics: if showStats=true was specified in the request this
     field will contain information about the document payload.
    :type statistics: ~textanalytics.models.DocumentStatistics
    :param bool is_error: Boolean check for error item when iterating over list of
     results. Always False for an instance of a DocumentLinkedEntities.
    """
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.entities = kwargs.get('entities', None)
        self.statistics = kwargs.get('statistics', None)
        self.is_error = False


class DocumentSentiment(object):
    """DocumentSentiment.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique, non-empty document identifier.
    :type id: str
    :param sentiment: Required. Predicted sentiment for document (Negative,
     Neutral, Positive, or Mixed). Possible values include: 'positive',
     'neutral', 'negative', 'mixed'
    :type sentiment: str or ~textanalytics.models.enum
    :param statistics:
    :type statistics: ~textanalytics.models.DocumentStatistics
    :param document_scores: Required. Document level sentiment confidence
     scores between 0 and 1 for each sentiment class.
    :type document_scores: object
    :param sentences: Required. Sentence level sentiment analysis.
    :type sentences: list[~textanalytics.models.SentenceSentiment]
    :param bool is_error: Boolean check for error item when iterating over list of
     results. Always False for an instance of a DocumentSentiment.
    """
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.sentiment = kwargs.get('sentiment', None)
        self.statistics = kwargs.get('statistics', None)
        self.document_scores = kwargs.get('document_scores', None)
        self.sentences = kwargs.get('sentences', None)
        self.is_error = False


class DocumentStatistics(object):
    """if showStats=true was specified in the request this field will contain
    information about the document payload.

    All required parameters must be populated in order to send to Azure.

    :param characters_count: Required. Number of text elements recognized in
     the document.
    :type characters_count: int
    :param transactions_count: Required. Number of transactions for the
     document.
    :type transactions_count: int
    """

    def __init__(self, **kwargs):
        self.characters_count = kwargs.get('characters_count', None)
        self.transactions_count = kwargs.get('transactions_count', None)

    @classmethod
    def _from_generated(cls, stats):
        if stats is None:
            return None
        return cls(
            characters_count=stats.characters_count,
            transactions_count=stats.transactions_count
        )


class DocumentError(object):
    """DocumentError.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Document Id.
    :type id: str
    :param error: Required. Document Error.
    :type error: object
    :param bool is_error: Boolean check for error item when iterating over list of
     results. Always True for an instance of a DocumentError.
    """

    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.error = kwargs.get('error', None)
        self.is_error = True


class LinkedEntity(object):
    """LinkedEntity.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Entity Linking formal name.
    :type name: str
    :param matches: Required. List of instances this entity appears in the
     text.
    :type matches: list[~textanalytics.models.Match]
    :param language: Required. Language used in the data source.
    :type language: str
    :param id: Unique identifier of the recognized entity from the data
     source.
    :type id: str
    :param url: Required. URL for the entity's page from the data source.
    :type url: str
    :param data_source: Required. Data source used to extract entity linking,
     such as Wiki/Bing etc.
    :type data_source: str
    :param bool is_error: Boolean check for error item when iterating over list of
     results. Always False for an instance of a LinkedEntity.
    """
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', None)
        self.matches = kwargs.get('matches', None)
        self.language = kwargs.get('language', None)
        self.id = kwargs.get('id', None)
        self.url = kwargs.get('url', None)
        self.data_source = kwargs.get('data_source', None)
        self.is_error = False

    @classmethod
    def _from_generated(cls, entity):
        return cls(
            name=entity.name,
            matches=[Match._from_generated(e) for e in entity.matches],
            language=entity.language,
            id=entity.id,
            url=entity.url,
            data_source=entity.data_source
        )


class Match(object):
    """Match.

    All required parameters must be populated in order to send to Azure.

    :param score: Required. (Optional) If a well-known item is recognized, a
     decimal number denoting the confidence level between 0 and 1 will be
     returned.
    :type score: float
    :param text: Required. Entity text as appears in the request.
    :type text: str
    :param offset: Required. Start position (in Unicode characters) for the
     entity match text.
    :type offset: int
    :param length: Required. Length (in Unicode characters) for the entity
     match text.
    :type length: int
    """
    def __init__(self, **kwargs):
        self.score = kwargs.get('score', None)
        self.text = kwargs.get('text', None)
        self.offset = kwargs.get('offset', None)
        self.length = kwargs.get('length', None)

    @classmethod
    def _from_generated(cls, match):
        return cls(
            score=match.score,
            text=match.text,
            offset=match.offset,
            length=match.length
        )


class SentenceSentiment(object):
    """SentenceSentiment.

    All required parameters must be populated in order to send to Azure.

    :param sentiment: Required. The predicted Sentiment for the sentence.
     Possible values include: 'positive', 'neutral', 'negative'
    :type sentiment: str or ~textanalytics.models.enum
    :param sentence_scores: Required. The sentiment confidence score between 0
     and 1 for the sentence for all classes.
    :type sentence_scores: object
    :param offset: Required. The sentence offset from the start of the
     document.
    :type offset: int
    :param length: Required. The length of the sentence by Unicode standard.
    :type length: int
    :param warnings: Required. The warnings generated for the sentence.
    :type warnings: list[str]
    """
    def __init__(self, **kwargs):
        self.sentiment = kwargs.get('sentiment', None)
        self.sentence_scores = kwargs.get('sentence_scores', None)
        self.offset = kwargs.get('offset', None)
        self.length = kwargs.get('length', None)
        self.warnings = kwargs.get('warnings', None)

    @classmethod
    def _from_generated(cls, sentence):
        return cls(
            sentiment=sentence.sentiment,
            sentence_scores=sentence.sentence_scores,
            offset=sentence.offset,
            length=sentence.length,
            warnings=sentence.warnings
        )
