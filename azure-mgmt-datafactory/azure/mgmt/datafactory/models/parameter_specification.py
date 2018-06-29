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


class ParameterSpecification(Model):
    """Definition of a single parameter for an entity.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Parameter type. Possible values include: 'Object',
     'String', 'Int', 'Float', 'Bool', 'Array', 'SecureString'
    :type type: str or ~azure.mgmt.datafactory.models.ParameterType
    :param default_value: Default value of parameter.
    :type default_value: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'default_value': {'key': 'defaultValue', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(ParameterSpecification, self).__init__(**kwargs)
        self.type = kwargs.get('type', None)
        self.default_value = kwargs.get('default_value', None)
