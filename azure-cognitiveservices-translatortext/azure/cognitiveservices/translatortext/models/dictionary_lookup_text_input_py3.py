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


class DictionaryLookupTextInput(Model):
    """Text needed for a dictionary lookup request .

    :param text:
    :type text: str
    """

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
    }

    def __init__(self, *, text: str=None, **kwargs) -> None:
        super(DictionaryLookupTextInput, self).__init__(**kwargs)
        self.text = text
