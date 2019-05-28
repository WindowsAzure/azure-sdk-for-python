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


class RegistryPassword(Model):
    """The login password for the container registry.

    :param name: The password name. Possible values include: 'password',
     'password2'
    :type name: str or
     ~azure.mgmt.containerregistry.v2018_02_01_preview.models.PasswordName
    :param value: The password value.
    :type value: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'PasswordName'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistryPassword, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.value = kwargs.get('value', None)
