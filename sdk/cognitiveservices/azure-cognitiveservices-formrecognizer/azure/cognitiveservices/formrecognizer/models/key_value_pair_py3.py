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


class KeyValuePair(Model):
    """Representation of a key-value pair as a list of key and value tokens.

    All required parameters must be populated in order to send to Azure.

    :param key: Required. Information about the extracted key in a key-value
     pair.
    :type key: ~azure.cognitiveservices.formrecognizer.models.KeyValueElement
    :param value: Required. Information about the extracted value in a
     key-value pair.
    :type value:
     ~azure.cognitiveservices.formrecognizer.models.KeyValueElement
    :param confidence: Required. Qualitative confidence measure.
    :type confidence: float
    """

    _validation = {
        'key': {'required': True},
        'value': {'required': True},
        'confidence': {'required': True},
    }

    _attribute_map = {
        'key': {'key': 'key', 'type': 'KeyValueElement'},
        'value': {'key': 'value', 'type': 'KeyValueElement'},
        'confidence': {'key': 'confidence', 'type': 'float'},
    }

    def __init__(self, *, key, value, confidence: float, **kwargs) -> None:
        super(KeyValuePair, self).__init__(**kwargs)
        self.key = key
        self.value = value
        self.confidence = confidence
