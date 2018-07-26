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


class Word(Model):
    """Word.

    :param bounding_box:
    :type bounding_box: list[int]
    :param text:
    :type text: str
    """

    _attribute_map = {
        'bounding_box': {'key': 'boundingBox', 'type': '[int]'},
        'text': {'key': 'text', 'type': 'str'},
    }

    def __init__(self, *, bounding_box=None, text: str=None, **kwargs) -> None:
        super(Word, self).__init__(**kwargs)
        self.bounding_box = bounding_box
        self.text = text
