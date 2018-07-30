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


class TermListMetadata(Model):
    """Term list metadata.

    :param key_one: Optional Key value pair to describe your list.
    :type key_one: str
    :param key_two: Optional Key value pair to describe your list.
    :type key_two: str
    """

    _attribute_map = {
        'key_one': {'key': 'Key One', 'type': 'str'},
        'key_two': {'key': 'Key Two', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(TermListMetadata, self).__init__(**kwargs)
        self.key_one = kwargs.get('key_one', None)
        self.key_two = kwargs.get('key_two', None)
