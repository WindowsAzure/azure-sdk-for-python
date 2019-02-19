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


class LanguagesResultTransliterationLanguageCode(Model):
    """LanguagesResultTransliterationLanguageCode.

    :param name:
    :type name: str
    :param native_name:
    :type native_name: str
    :param scripts:
    :type scripts:
     list[~azure.cognitiveservices.translatortext.models.LanguagesResultTransliterationLanguageCodeScriptsItem]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'native_name': {'key': 'nativeName', 'type': 'str'},
        'scripts': {'key': 'scripts', 'type': '[LanguagesResultTransliterationLanguageCodeScriptsItem]'},
    }

    def __init__(self, **kwargs):
        super(LanguagesResultTransliterationLanguageCode, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.native_name = kwargs.get('native_name', None)
        self.scripts = kwargs.get('scripts', None)
