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


class PatternCreateObject(Model):
    """Object model for creating a Pattern feature.

    :param pattern: The Regular Expression to match.
    :type pattern: str
    :param name: Name of the feature.
    :type name: str
    """

    _attribute_map = {
        'pattern': {'key': 'pattern', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, pattern: str=None, name: str=None, **kwargs) -> None:
        super(PatternCreateObject, self).__init__(**kwargs)
        self.pattern = pattern
        self.name = name
