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


class Usage(Model):
    """A single usage result.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar unit: Unit of the usage result
    :vartype unit: str
    :ivar current_value: The current usage of the resource
    :vartype current_value: int
    :ivar limit: The maximum permitted usage of the resource.
    :vartype limit: int
    :ivar name: The name object of the resource
    :vartype name: ~azure.mgmt.containerinstance.models.UsageName
    """

    _validation = {
        'unit': {'readonly': True},
        'current_value': {'readonly': True},
        'limit': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'unit': {'key': 'unit', 'type': 'str'},
        'current_value': {'key': 'currentValue', 'type': 'int'},
        'limit': {'key': 'limit', 'type': 'int'},
        'name': {'key': 'name', 'type': 'UsageName'},
    }

    def __init__(self, **kwargs) -> None:
        super(Usage, self).__init__(**kwargs)
        self.unit = None
        self.current_value = None
        self.limit = None
        self.name = None
