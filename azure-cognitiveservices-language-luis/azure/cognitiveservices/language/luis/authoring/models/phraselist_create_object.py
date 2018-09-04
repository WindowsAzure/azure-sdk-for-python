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


class PhraselistCreateObject(Model):
    """Object model for creating a phraselist model.

    :param phrases: List of comma-separated phrases that represent the
     Phraselist.
    :type phrases: str
    :param name: The Phraselist name.
    :type name: str
    :param is_exchangeable: An exchangeable phrase list feature are serves as
     single feature to the LUIS underlying training algorithm. It is used as a
     lexicon lookup feature where its value is 1 if the lexicon contains a
     given word or 0 if it doesn’t. Think of an exchangeable as a synonyms
     list. A non-exchangeable phrase list feature has all the phrases in the
     list serve as separate features to the underlying training algorithm. So,
     if you your phrase list feature contains 5 phrases, they will be mapped to
     5 separate features. You can think of the non-exchangeable phrase list
     feature as an additional bag of words that you are willing to add to LUIS
     existing vocabulary features. Think of a non-exchangeable as set of
     different words. Default value is true. Default value: True .
    :type is_exchangeable: bool
    """

    _attribute_map = {
        'phrases': {'key': 'phrases', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'is_exchangeable': {'key': 'isExchangeable', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(PhraselistCreateObject, self).__init__(**kwargs)
        self.phrases = kwargs.get('phrases', None)
        self.name = kwargs.get('name', None)
        self.is_exchangeable = kwargs.get('is_exchangeable', True)
