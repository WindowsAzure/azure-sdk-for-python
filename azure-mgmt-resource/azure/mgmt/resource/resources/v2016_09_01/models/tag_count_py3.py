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


class TagCount(Model):
    """Tag count.

    :param type: Type of count.
    :type type: str
    :param value: Value of count.
    :type value: int
    """

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'value': {'key': 'value', 'type': 'int'},
    }

    def __init__(self, *, type: str=None, value: int=None, **kwargs) -> None:
        super(TagCount, self).__init__(**kwargs)
        self.type = type
        self.value = value
