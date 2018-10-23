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

from .resource_py3 import Resource


class BotChannel(Resource):
    """Bot channel resource definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Specifies the resource ID.
    :vartype id: str
    :ivar name: Specifies the name of the resource.
    :vartype name: str
    :param location: Specifies the location of the resource.
    :type location: str
    :ivar type: Specifies the type of the resource.
    :vartype type: str
    :param tags: Contains resource tags defined as key/value pairs.
    :type tags: dict[str, str]
    :param sku: Gets or sets the SKU of the resource.
    :type sku: ~azure.mgmt.botservice.models.Sku
    :param kind: Required. Gets or sets the Kind of the resource. Possible
     values include: 'sdk', 'designer', 'bot', 'function'
    :type kind: str or ~azure.mgmt.botservice.models.Kind
    :param etag: Entity Tag
    :type etag: str
    :param properties: The set of properties specific to bot channel resource
    :type properties: ~azure.mgmt.botservice.models.Channel
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'kind': {'key': 'kind', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'Channel'},
    }

    def __init__(self, *, location: str=None, tags=None, sku=None, kind=None, etag: str=None, properties=None, **kwargs) -> None:
        super(BotChannel, self).__init__(location=location, tags=tags, sku=sku, kind=kind, etag=etag, **kwargs)
        self.properties = properties
