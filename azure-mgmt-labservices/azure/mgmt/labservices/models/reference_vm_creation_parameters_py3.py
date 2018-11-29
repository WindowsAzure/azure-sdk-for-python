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


class ReferenceVmCreationParameters(Model):
    """Creation parameters for Reference Vm.

    All required parameters must be populated in order to send to Azure.

    :param user_name: Required. The username of the virtual machine
    :type user_name: str
    :param password: Required. The password of the virtual machine.
    :type password: str
    """

    _validation = {
        'user_name': {'required': True},
        'password': {'required': True},
    }

    _attribute_map = {
        'user_name': {'key': 'userName', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
    }

    def __init__(self, *, user_name: str, password: str, **kwargs) -> None:
        super(ReferenceVmCreationParameters, self).__init__(**kwargs)
        self.user_name = user_name
        self.password = password
