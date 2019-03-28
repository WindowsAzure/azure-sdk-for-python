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


class DeploymentExtended(Model):
    """Deployment information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The ID of the deployment.
    :vartype id: str
    :ivar name: The name of the deployment.
    :vartype name: str
    :ivar type: The type of the deployment.
    :vartype type: str
    :param location: the location of the deployment.
    :type location: str
    :param properties: Deployment properties.
    :type properties:
     ~azure.mgmt.resource.resources.v2018_05_01.models.DeploymentPropertiesExtended
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'DeploymentPropertiesExtended'},
    }

    def __init__(self, **kwargs):
        super(DeploymentExtended, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = kwargs.get('location', None)
        self.properties = kwargs.get('properties', None)
