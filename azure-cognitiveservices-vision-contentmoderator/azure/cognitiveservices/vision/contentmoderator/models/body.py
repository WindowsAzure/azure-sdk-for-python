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


class Body(Model):
    """Body.

    :param name: Name of the list.
    :type name: str
    :param description: Description of the list.
    :type description: str
    :param metadata: Metadata of the list.
    :type metadata: dict[str, str]
    """

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str'},
        'description': {'key': 'Description', 'type': 'str'},
        'metadata': {'key': 'Metadata', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(Body, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.description = kwargs.get('description', None)
        self.metadata = kwargs.get('metadata', None)
