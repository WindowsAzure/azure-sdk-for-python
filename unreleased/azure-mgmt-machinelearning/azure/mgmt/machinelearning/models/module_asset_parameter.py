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


class ModuleAssetParameter(Model):
    """Parameter definition for a module asset.

    :param name: Parameter name.
    :type name: str
    :param parameter_type: Parameter type.
    :type parameter_type: str
    :param mode_values_info: Definitions for nested interface parameters if
     this is a complex module parameter.
    :type mode_values_info: dict
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'parameter_type': {'key': 'parameterType', 'type': 'str'},
        'mode_values_info': {'key': 'modeValuesInfo', 'type': '{ModeValueInfo}'},
    }

    def __init__(self, name=None, parameter_type=None, mode_values_info=None):
        self.name = name
        self.parameter_type = parameter_type
        self.mode_values_info = mode_values_info
