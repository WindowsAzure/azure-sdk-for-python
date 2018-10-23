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


class ApplicationUpdateObject(Model):
    """Object model for updating the name or description of an application.

    :param name: The application's new name.
    :type name: str
    :param description: The application's new description.
    :type description: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, description: str=None, **kwargs) -> None:
        super(ApplicationUpdateObject, self).__init__(**kwargs)
        self.name = name
        self.description = description
