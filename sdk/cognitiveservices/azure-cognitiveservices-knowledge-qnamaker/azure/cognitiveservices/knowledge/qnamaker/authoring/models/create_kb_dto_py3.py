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


class CreateKbDTO(Model):
    """Post body schema for CreateKb operation.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Friendly name for the knowledgebase.
    :type name: str
    :param qna_list: List of Q-A (QnADTO) to be added to the knowledgebase.
     Q-A Ids are assigned by the service and should be omitted.
    :type qna_list:
     list[~azure.cognitiveservices.knowledge.qnamaker.authoring.models.QnADTO]
    :param urls: List of URLs to be used for extracting Q-A.
    :type urls: list[str]
    :param files: List of files from which to Extract Q-A.
    :type files:
     list[~azure.cognitiveservices.knowledge.qnamaker.authoring.models.FileDTO]
    :param enable_hierarchical_extraction: Enable hierarchical extraction of
     Q-A from files and urls. Value to be considered False if this field is not
     present.
    :type enable_hierarchical_extraction: bool
    :param default_answer_used_for_extraction: Text string to be used as the
     answer in any Q-A which has no extracted answer from the document but has
     a hierarchy. Required when EnableHierarchicalExtraction field is set to
     True.
    :type default_answer_used_for_extraction: str
    :param language: Language of the knowledgebase. Please find the list of
     supported languages <a
     href="https://aka.ms/qnamaker-languages#languages-supported"
     target="_blank">here</a>.
    :type language: str
    :param enable_multiple_languages: Set to true to enable creating KBs in
     different languages for the same resource.
    :type enable_multiple_languages: bool
    :param default_answer: Default answer sent to user if no good match is
     found in the KB.
    :type default_answer: str
    """

    _validation = {
        'name': {'required': True, 'max_length': 100, 'min_length': 1},
        'default_answer_used_for_extraction': {'max_length': 300, 'min_length': 1},
        'language': {'max_length': 100, 'min_length': 1},
        'default_answer': {'max_length': 300, 'min_length': 1},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'qna_list': {'key': 'qnaList', 'type': '[QnADTO]'},
        'urls': {'key': 'urls', 'type': '[str]'},
        'files': {'key': 'files', 'type': '[FileDTO]'},
        'enable_hierarchical_extraction': {'key': 'enableHierarchicalExtraction', 'type': 'bool'},
        'default_answer_used_for_extraction': {'key': 'defaultAnswerUsedForExtraction', 'type': 'str'},
        'language': {'key': 'language', 'type': 'str'},
        'enable_multiple_languages': {'key': 'enableMultipleLanguages', 'type': 'bool'},
        'default_answer': {'key': 'defaultAnswer', 'type': 'str'},
    }

    def __init__(self, *, name: str, qna_list=None, urls=None, files=None, enable_hierarchical_extraction: bool=None, default_answer_used_for_extraction: str=None, language: str=None, enable_multiple_languages: bool=None, default_answer: str=None, **kwargs) -> None:
        super(CreateKbDTO, self).__init__(**kwargs)
        self.name = name
        self.qna_list = qna_list
        self.urls = urls
        self.files = files
        self.enable_hierarchical_extraction = enable_hierarchical_extraction
        self.default_answer_used_for_extraction = default_answer_used_for_extraction
        self.language = language
        self.enable_multiple_languages = enable_multiple_languages
        self.default_answer = default_answer
