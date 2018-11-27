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

from .sub_resource_py3 import SubResource


class ConnectionSharedKey(SubResource):
    """Response for GetConnectionSharedKey API service call.

    All required parameters must be populated in order to send to Azure.

    :param id: Resource ID.
    :type id: str
    :param value: Required. The virtual network connection shared key value.
    :type value: str
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, *, value: str, id: str=None, **kwargs) -> None:
        super(ConnectionSharedKey, self).__init__(id=id, **kwargs)
        self.value = value
