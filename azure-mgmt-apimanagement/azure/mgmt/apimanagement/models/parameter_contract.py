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


class ParameterContract(Model):
    """Operation parameters details.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Parameter name.
    :type name: str
    :param description: Parameter description.
    :type description: str
    :param type: Required. Parameter type.
    :type type: str
    :param default_value: Default parameter value.
    :type default_value: str
    :param required: whether parameter is required or not.
    :type required: bool
    :param values: Parameter values.
    :type values: list[str]
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'default_value': {'key': 'defaultValue', 'type': 'str'},
        'required': {'key': 'required', 'type': 'bool'},
        'values': {'key': 'values', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ParameterContract, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.description = kwargs.get('description', None)
        self.type = kwargs.get('type', None)
        self.default_value = kwargs.get('default_value', None)
        self.required = kwargs.get('required', None)
        self.values = kwargs.get('values', None)
