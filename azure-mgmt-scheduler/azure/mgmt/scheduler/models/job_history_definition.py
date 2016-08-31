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


class JobHistoryDefinition(Model):
    """JobHistoryDefinition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Gets the job history identifier.
    :vartype id: str
    :ivar type: Gets the job history resource type.
    :vartype type: str
    :ivar name: Gets the job history name.
    :vartype name: str
    :ivar properties: Gets or sets the job history properties.
    :vartype properties: :class:`JobHistoryDefinitionProperties
     <azure.mgmt.scheduler.models.JobHistoryDefinitionProperties>`
    """ 

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'properties': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'JobHistoryDefinitionProperties'},
    }

    def __init__(self):
        self.id = None
        self.type = None
        self.name = None
        self.properties = None
