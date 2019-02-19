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


class DictionaryExampleResultItemExamplesItem(Model):
    """DictionaryExampleResultItemExamplesItem.

    :param source_prefix:
    :type source_prefix: str
    :param source_term:
    :type source_term: str
    :param source_suffix:
    :type source_suffix: str
    :param target_prefix:
    :type target_prefix: str
    :param target_term:
    :type target_term: str
    :param target_suffix:
    :type target_suffix: str
    """

    _attribute_map = {
        'source_prefix': {'key': 'sourcePrefix', 'type': 'str'},
        'source_term': {'key': 'sourceTerm', 'type': 'str'},
        'source_suffix': {'key': 'sourceSuffix', 'type': 'str'},
        'target_prefix': {'key': 'targetPrefix', 'type': 'str'},
        'target_term': {'key': 'targetTerm', 'type': 'str'},
        'target_suffix': {'key': 'targetSuffix', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(DictionaryExampleResultItemExamplesItem, self).__init__(**kwargs)
        self.source_prefix = kwargs.get('source_prefix', None)
        self.source_term = kwargs.get('source_term', None)
        self.source_suffix = kwargs.get('source_suffix', None)
        self.target_prefix = kwargs.get('target_prefix', None)
        self.target_term = kwargs.get('target_term', None)
        self.target_suffix = kwargs.get('target_suffix', None)
