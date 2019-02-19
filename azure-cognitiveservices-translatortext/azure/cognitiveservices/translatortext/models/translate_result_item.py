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


class TranslateResultItem(Model):
    """TranslateResultItem.

    :param translation:
    :type translation:
     list[~azure.cognitiveservices.translatortext.models.TranslateResultItemTranslationItem]
    """

    _attribute_map = {
        'translation': {'key': 'translation', 'type': '[TranslateResultItemTranslationItem]'},
    }

    def __init__(self, **kwargs):
        super(TranslateResultItem, self).__init__(**kwargs)
        self.translation = kwargs.get('translation', None)
