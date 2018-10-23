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


class PrebuiltEntity(Model):
    """Prebuilt Entity Extractor.

    :param name:
    :type name: str
    :param roles:
    :type roles: list[str]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'roles': {'key': 'roles', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(PrebuiltEntity, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.roles = kwargs.get('roles', None)
