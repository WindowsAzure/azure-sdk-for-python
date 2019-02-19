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


class LanguagesResult(Model):
    """Example of a successful languages request.

    :param translation:
    :type translation:
     ~azure.cognitiveservices.translatortext.models.LanguagesResultTranslation
    :param transliteration:
    :type transliteration:
     ~azure.cognitiveservices.translatortext.models.LanguagesResultTransliteration
    :param dictionary:
    :type dictionary:
     ~azure.cognitiveservices.translatortext.models.LanguagesResultDictionary
    """

    _attribute_map = {
        'translation': {'key': 'translation', 'type': 'LanguagesResultTranslation'},
        'transliteration': {'key': 'transliteration', 'type': 'LanguagesResultTransliteration'},
        'dictionary': {'key': 'dictionary', 'type': 'LanguagesResultDictionary'},
    }

    def __init__(self, *, translation=None, transliteration=None, dictionary=None, **kwargs) -> None:
        super(LanguagesResult, self).__init__(**kwargs)
        self.translation = translation
        self.transliteration = transliteration
        self.dictionary = dictionary
