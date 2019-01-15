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

from .property_value import PropertyValue


class Int64PropertyValue(PropertyValue):
    """Describes a Service Fabric property value of type Int64.

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    :param data: Required. The data of the property value.
    :type data: str
    """

    _validation = {
        'kind': {'required': True},
        'data': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'Kind', 'type': 'str'},
        'data': {'key': 'Data', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Int64PropertyValue, self).__init__(**kwargs)
        self.data = kwargs.get('data', None)
        self.kind = 'Int64'
