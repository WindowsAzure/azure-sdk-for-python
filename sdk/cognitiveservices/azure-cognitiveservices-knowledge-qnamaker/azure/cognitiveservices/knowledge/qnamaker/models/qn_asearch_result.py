# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class QnASearchResult(Model):
    """Represents Search Result.

    :param questions: List of questions.
    :type questions: list[str]
    :param answer: Answer.
    :type answer: str
    :param score: Search result score.
    :type score: float
    :param id: Id of the QnA result.
    :type id: int
    :param source: Source of QnA result.
    :type source: str
    :param metadata: List of metadata.
    :type metadata:
     list[~azure.cognitiveservices.knowledge.qnamaker.models.MetadataDTO]
    :param context: Context object of the QnA
    :type context:
     ~azure.cognitiveservices.knowledge.qnamaker.models.QnASearchResultContext
    :param answer_span: Answer span object of QnA with respect to user's
     question.
    :type answer_span:
     ~azure.cognitiveservices.knowledge.qnamaker.models.QnASearchResultAnswerSpan
    """

    _attribute_map = {
        'questions': {'key': 'questions', 'type': '[str]'},
        'answer': {'key': 'answer', 'type': 'str'},
        'score': {'key': 'score', 'type': 'float'},
        'id': {'key': 'id', 'type': 'int'},
        'source': {'key': 'source', 'type': 'str'},
        'metadata': {'key': 'metadata', 'type': '[MetadataDTO]'},
        'context': {'key': 'context', 'type': 'QnASearchResultContext'},
        'answer_span': {'key': 'answerSpan', 'type': 'QnASearchResultAnswerSpan'},
    }

    def __init__(self, **kwargs):
        super(QnASearchResult, self).__init__(**kwargs)
        self.questions = kwargs.get('questions', None)
        self.answer = kwargs.get('answer', None)
        self.score = kwargs.get('score', None)
        self.id = kwargs.get('id', None)
        self.source = kwargs.get('source', None)
        self.metadata = kwargs.get('metadata', None)
        self.context = kwargs.get('context', None)
        self.answer_span = kwargs.get('answer_span', None)
