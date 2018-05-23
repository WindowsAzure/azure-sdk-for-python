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


class JobDefinition(Model):
    """JobDefinition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Gets the job resource identifier.
    :vartype id: str
    :ivar type: Gets the job resource type.
    :vartype type: str
    :ivar name: Gets the job resource name.
    :vartype name: str
    :param properties: Gets or sets the job properties.
    :type properties: ~azure.mgmt.scheduler.models.JobProperties
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'JobProperties'},
    }

    def __init__(self, *, properties=None, **kwargs) -> None:
        super(JobDefinition, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.name = None
        self.properties = properties
