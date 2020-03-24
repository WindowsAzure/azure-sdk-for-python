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


class QnASearchResultList(Model):
    """Represents List of Question Answers.

    :param answers: Represents Search Result list.
    :type answers:
     list[~azure.cognitiveservices.knowledge.qnamaker.runtime.models.QnASearchResult]
    """

    _attribute_map = {
        'answers': {'key': 'answers', 'type': '[QnASearchResult]'},
    }

    def __init__(self, *, answers=None, **kwargs) -> None:
        super(QnASearchResultList, self).__init__(**kwargs)
        self.answers = answers
