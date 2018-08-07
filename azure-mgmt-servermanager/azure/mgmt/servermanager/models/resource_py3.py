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


class Resource(Model):
    """Resource Manager Resource Information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Manager Resource ID.
    :vartype id: str
    :ivar type: Resource Manager Resource Type.
    :vartype type: str
    :ivar name: Resource Manager Resource Name.
    :vartype name: str
    :ivar location: Resource Manager Resource Location.
    :vartype location: str
    :param tags: Resource Manager Resource Tags.
    :type tags: dict[str, str]
    :param etag:
    :type etag: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'location': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, tags=None, etag: str=None, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.name = None
        self.location = None
        self.tags = tags
        self.etag = etag
