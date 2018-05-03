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


class RepetitionIndex(Model):
    """The workflow run action repetition index.

    All required parameters must be populated in order to send to Azure.

    :param scope_name: The scope.
    :type scope_name: str
    :param item_index: Required. The index.
    :type item_index: int
    """

    _validation = {
        'item_index': {'required': True},
    }

    _attribute_map = {
        'scope_name': {'key': 'scopeName', 'type': 'str'},
        'item_index': {'key': 'itemIndex', 'type': 'int'},
    }

    def __init__(self, *, item_index: int, scope_name: str=None, **kwargs) -> None:
        super(RepetitionIndex, self).__init__(**kwargs)
        self.scope_name = scope_name
        self.item_index = item_index
