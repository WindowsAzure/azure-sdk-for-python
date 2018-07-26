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

from .patch_tracked_resource import PatchTrackedResource


class PatchVault(PatchTrackedResource):
    """Patch Resource information, as returned by the resource provider.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id represents the complete path to the resource.
    :vartype id: str
    :ivar name: Resource name associated with the resource.
    :vartype name: str
    :ivar type: Resource type represents the complete path of the form
     Namespace/ResourceType/ResourceType/...
    :vartype type: str
    :param e_tag: Optional ETag.
    :type e_tag: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param properties:
    :type properties: ~azure.mgmt.recoveryservices.models.VaultProperties
    :param sku:
    :type sku: ~azure.mgmt.recoveryservices.models.Sku
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
        'e_tag': {'key': 'eTag', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'VaultProperties'},
        'sku': {'key': 'sku', 'type': 'Sku'},
    }

    def __init__(self, **kwargs):
        super(PatchVault, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)
        self.sku = kwargs.get('sku', None)
