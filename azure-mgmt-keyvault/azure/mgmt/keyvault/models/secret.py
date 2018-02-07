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

from .resource import Resource


class Secret(Resource):
    """Resource information with extended details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The Azure Resource Manager resource ID for the key vault.
    :vartype id: str
    :ivar name: The name of the key vault.
    :vartype name: str
    :ivar type: The resource type of the key vault.
    :vartype type: str
    :param location: The supported Azure location where the key vault should
     be created.
    :type location: str
    :param tags: The tags that will be assigned to the key vault.
    :type tags: dict[str, str]
    :param properties: Properties of the secret
    :type properties: ~azure.mgmt.keyvault.models.SecretProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'properties': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'SecretProperties'},
    }

    def __init__(self, location, properties, tags=None):
        super(Secret, self).__init__(location=location, tags=tags)
        self.properties = properties
