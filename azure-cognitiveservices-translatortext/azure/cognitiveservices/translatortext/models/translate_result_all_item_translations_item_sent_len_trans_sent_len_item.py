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


class TranslateResultAllItemTranslationsItemSentLenTransSentLenItem(Model):
    """TranslateResultAllItemTranslationsItemSentLenTransSentLenItem.

    :param integer:
    :type integer: int
    """

    _attribute_map = {
        'integer': {'key': 'integer', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(TranslateResultAllItemTranslationsItemSentLenTransSentLenItem, self).__init__(**kwargs)
        self.integer = kwargs.get('integer', None)
