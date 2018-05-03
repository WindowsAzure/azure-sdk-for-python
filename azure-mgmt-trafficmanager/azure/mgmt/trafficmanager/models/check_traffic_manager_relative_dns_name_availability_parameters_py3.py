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


class CheckTrafficManagerRelativeDnsNameAvailabilityParameters(Model):
    """Parameters supplied to check Traffic Manager name operation.

    :param name: The name of the resource.
    :type name: str
    :param type: The type of the resource.
    :type type: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, type: str=None, **kwargs) -> None:
        super(CheckTrafficManagerRelativeDnsNameAvailabilityParameters, self).__init__(**kwargs)
        self.name = name
        self.type = type
