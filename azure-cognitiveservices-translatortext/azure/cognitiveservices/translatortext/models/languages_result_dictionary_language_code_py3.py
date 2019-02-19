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


class LanguagesResultDictionaryLanguageCode(Model):
    """LanguagesResultDictionaryLanguageCode.

    :param name:
    :type name: str
    :param native_name:
    :type native_name: str
    :param dir:
    :type dir: str
    :param translations:
    :type translations:
     list[~azure.cognitiveservices.translatortext.models.LanguagesResultDictionaryLanguageCodeTranslationsItem]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'native_name': {'key': 'nativeName', 'type': 'str'},
        'dir': {'key': 'dir', 'type': 'str'},
        'translations': {'key': 'translations', 'type': '[LanguagesResultDictionaryLanguageCodeTranslationsItem]'},
    }

    def __init__(self, *, name: str=None, native_name: str=None, dir: str=None, translations=None, **kwargs) -> None:
        super(LanguagesResultDictionaryLanguageCode, self).__init__(**kwargs)
        self.name = name
        self.native_name = native_name
        self.dir = dir
        self.translations = translations
