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


class SSN(Model):
    """Detected SSN details.

    :param text: Detected SSN in the input text content.
    :type text: str
    :param index: Index(Location) of the SSN in the input text content.
    :type index: int
    """

    _attribute_map = {
        'text': {'key': 'Text', 'type': 'str'},
        'index': {'key': 'Index', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(SSN, self).__init__(**kwargs)
        self.text = kwargs.get('text', None)
        self.index = kwargs.get('index', None)
