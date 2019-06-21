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


class MetadataValue(Model):
    """Represents a metric metadata value.

    :param name: the name of the metadata.
    :type name: ~azure.mgmt.monitor.v2018_01_01.models.LocalizableString
    :param value: the value of the metadata.
    :type value: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'LocalizableString'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, *, name=None, value: str=None, **kwargs) -> None:
        super(MetadataValue, self).__init__(**kwargs)
        self.name = name
        self.value = value
