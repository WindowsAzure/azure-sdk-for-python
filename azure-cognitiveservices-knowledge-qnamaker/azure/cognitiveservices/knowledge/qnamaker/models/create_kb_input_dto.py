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


class CreateKbInputDTO(Model):
    """Input to create KB.

    :param qna_list: List of QNA to be added to the index. Ids are generated
     by the service and should be omitted.
    :type qna_list:
     list[~azure.cognitiveservices.knowledge.qnamaker.models.QnADTO]
    :param urls: List of URLs to be added to knowledgebase.
    :type urls: list[str]
    :param files: List of files to be added to knowledgebase.
    :type files:
     list[~azure.cognitiveservices.knowledge.qnamaker.models.FileDTO]
    """

    _attribute_map = {
        'qna_list': {'key': 'qnaList', 'type': '[QnADTO]'},
        'urls': {'key': 'urls', 'type': '[str]'},
        'files': {'key': 'files', 'type': '[FileDTO]'},
    }

    def __init__(self, **kwargs):
        super(CreateKbInputDTO, self).__init__(**kwargs)
        self.qna_list = kwargs.get('qna_list', None)
        self.urls = kwargs.get('urls', None)
        self.files = kwargs.get('files', None)
