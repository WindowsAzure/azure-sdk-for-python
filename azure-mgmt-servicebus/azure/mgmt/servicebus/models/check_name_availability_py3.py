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


class CheckNameAvailability(Model):
    """Description of a Check Name availability request properties.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The Name to check the namespce name availability
     and The namespace name can contain only letters, numbers, and hyphens. The
     namespace must start with a letter, and it must end with a letter or
     number.
    :type name: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, name: str, **kwargs) -> None:
        super(CheckNameAvailability, self).__init__(**kwargs)
        self.name = name
