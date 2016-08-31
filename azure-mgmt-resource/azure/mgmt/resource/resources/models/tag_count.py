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
    :type value: str
    """ 

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, type=None, value=None):
        self.type = type
        self.value = value
