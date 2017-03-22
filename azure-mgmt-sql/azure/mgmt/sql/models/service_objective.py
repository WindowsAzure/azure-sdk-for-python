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

from .sub_resource import SubResource


class ServiceObjective(SubResource):
    """Represents a database service objective.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Resource name
    :vartype name: str
    :ivar id: The resource ID.
    :vartype id: str
    :ivar service_objective_name: The name for the service objective.
    :vartype service_objective_name: str
    :ivar is_default: Gets whether the service level objective is the default
     service objective.
    :vartype is_default: bool
    :ivar is_system: Gets whether the service level objective is a system
     service objective.
    :vartype is_system: bool
    :ivar description: The description for the service level objective.
    :vartype description: str
    :ivar enabled: Gets whether the service level objective is enabled.
    :vartype enabled: bool
    """

    _validation = {
        'name': {'readonly': True},
        'id': {'readonly': True},
        'service_objective_name': {'readonly': True},
        'is_default': {'readonly': True},
        'is_system': {'readonly': True},
        'description': {'readonly': True},
        'enabled': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'service_objective_name': {'key': 'properties.serviceObjectiveName', 'type': 'str'},
        'is_default': {'key': 'properties.isDefault', 'type': 'bool'},
        'is_system': {'key': 'properties.isSystem', 'type': 'bool'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
    }

    def __init__(self):
        super(ServiceObjective, self).__init__()
        self.service_objective_name = None
        self.is_default = None
        self.is_system = None
        self.description = None
        self.enabled = None
