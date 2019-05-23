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


class AvailableDelegation(Model):
    """The serviceName of an AvailableDelegation indicates a possible delegation
    for a subnet.

    :param name: The name of the AvailableDelegation resource.
    :type name: str
    :param id: A unique identifier of the AvailableDelegation resource.
    :type id: str
    :param type: Resource type.
    :type type: str
    :param service_name: The name of the service and resource
    :type service_name: str
    :param actions: Describes the actions permitted to the service upon
     delegation
    :type actions: list[str]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'service_name': {'key': 'serviceName', 'type': 'str'},
        'actions': {'key': 'actions', 'type': '[str]'},
    }

    def __init__(self, *, name: str=None, id: str=None, type: str=None, service_name: str=None, actions=None, **kwargs) -> None:
        super(AvailableDelegation, self).__init__(**kwargs)
        self.name = name
        self.id = id
        self.type = type
        self.service_name = service_name
        self.actions = actions
