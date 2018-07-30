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


class TranscriptModerationBodyItemTermsItem(Model):
    """TranscriptModerationBodyItemTermsItem.

    All required parameters must be populated in order to send to Azure.

    :param index: Required. Index of the word
    :type index: int
    :param term: Required. Detected word.
    :type term: str
    """

    _validation = {
        'index': {'required': True},
        'term': {'required': True},
    }

    _attribute_map = {
        'index': {'key': 'Index', 'type': 'int'},
        'term': {'key': 'Term', 'type': 'str'},
    }

    def __init__(self, *, index: int, term: str, **kwargs) -> None:
        super(TranscriptModerationBodyItemTermsItem, self).__init__(**kwargs)
        self.index = index
        self.term = term
