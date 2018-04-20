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


class GenericResource(Resource):
    """Resource information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param plan: The plan of the resource.
    :type plan: ~azure.mgmt.resource.resources.v2016_02_01.models.Plan
    :param properties: The resource properties.
    :type properties: object
    :param kind: The kind of the resource.
    :type kind: str
    :param managed_by: Id of the resource that manages this resource.
    :type managed_by: str
    :param sku: The sku of the resource.
    :type sku: ~azure.mgmt.resource.resources.v2016_02_01.models.Sku
    :param identity: The identity of the resource.
    :type identity: ~azure.mgmt.resource.resources.v2016_02_01.models.Identity
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
        'tags': {'key': 'tags', 'type': '{str}'},
        'plan': {'key': 'plan', 'type': 'Plan'},
        'properties': {'key': 'properties', 'type': 'object'},
        'kind': {'key': 'kind', 'type': 'str'},
        'managed_by': {'key': 'managedBy', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'identity': {'key': 'identity', 'type': 'Identity'},
    }

    def __init__(self, *, location: str=None, tags=None, plan=None, properties=None, kind: str=None, managed_by: str=None, sku=None, identity=None, **kwargs) -> None:
        super(GenericResource, self).__init__(location=location, tags=tags, **kwargs)
        self.plan = plan
        self.properties = properties
        self.kind = kind
        self.managed_by = managed_by
        self.sku = sku
        self.identity = identity
