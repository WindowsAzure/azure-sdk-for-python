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


class ParameterInfo(Model):
    """Information about an artifact's parameter.

    :param name: The name of the artifact parameter.
    :type name: str
    :param value: The value of the artifact parameter.
    :type value: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, value: str=None, **kwargs) -> None:
        super(ParameterInfo, self).__init__(**kwargs)
        self.name = name
        self.value = value
