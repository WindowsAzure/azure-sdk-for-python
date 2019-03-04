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


class MetadataDTO(Model):
    """Name - value pair of metadata.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Metadata name.
    :type name: str
    :param value: Required. Metadata value.
    :type value: str
    """

    _validation = {
        'name': {'required': True, 'max_length': 100, 'min_length': 1},
        'value': {'required': True, 'max_length': 500, 'min_length': 1},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, *, name: str, value: str, **kwargs) -> None:
        super(MetadataDTO, self).__init__(**kwargs)
        self.name = name
        self.value = value
