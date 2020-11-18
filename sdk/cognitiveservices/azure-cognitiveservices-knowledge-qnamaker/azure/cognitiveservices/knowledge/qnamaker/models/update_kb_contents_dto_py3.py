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


class UpdateKbContentsDTO(Model):
    """PATCH body schema for Update operation in Update Kb.

    :param name: Friendly name for the knowledgebase.
    :type name: str
    :param qna_list: List of Q-A (UpdateQnaDTO) to be added to the
     knowledgebase.
    :type qna_list:
     list[~azure.cognitiveservices.knowledge.qnamaker.models.UpdateQnaDTO]
    :param urls: List of existing URLs to be refreshed. The content will be
     extracted again and re-indexed.
    :type urls: list[str]
    :param default_answer: Default answer sent to user if no good match is
     found in the KB.
    :type default_answer: str
    """

    _validation = {
        'default_answer': {'max_length': 300, 'min_length': 1},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'qna_list': {'key': 'qnaList', 'type': '[UpdateQnaDTO]'},
        'urls': {'key': 'urls', 'type': '[str]'},
        'default_answer': {'key': 'defaultAnswer', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, qna_list=None, urls=None, default_answer: str=None, **kwargs) -> None:
        super(UpdateKbContentsDTO, self).__init__(**kwargs)
        self.name = name
        self.qna_list = qna_list
        self.urls = urls
        self.default_answer = default_answer
