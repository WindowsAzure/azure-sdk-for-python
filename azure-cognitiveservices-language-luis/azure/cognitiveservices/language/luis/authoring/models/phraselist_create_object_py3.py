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
    :param is_exchangeable: An interchangeable phrase list feature serves as a
     list of synonyms for training. A non-exchangeable phrase list serves as
     separate features for training. So, if your non-interchangeable phrase
     list contains 5 phrases, they will be mapped to 5 separate features. You
     can think of the non-interchangeable phrase list as an additional bag of
     words to add to LUIS existing vocabulary features. It is used as a lexicon
     lookup feature where its value is 1 if the lexicon contains a given word
     or 0 if it doesn’t.  Default value is true. Default value: True .
    :type is_exchangeable: bool
    """

    _attribute_map = {
        'phrases': {'key': 'phrases', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'is_exchangeable': {'key': 'isExchangeable', 'type': 'bool'},
    }

    def __init__(self, *, phrases: str=None, name: str=None, is_exchangeable: bool=True, **kwargs) -> None:
        super(PhraselistCreateObject, self).__init__(**kwargs)
        self.phrases = phrases
        self.name = name
        self.is_exchangeable = is_exchangeable
