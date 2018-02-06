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

from .proxy_resource import ProxyResource


class Database(ProxyResource):
    """Represents a Database.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param charset: The charset of the database.
    :type charset: str
    :param collation: The collation of the database.
    :type collation: str
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
        'charset': {'key': 'properties.charset', 'type': 'str'},
        'collation': {'key': 'properties.collation', 'type': 'str'},
    }

    def __init__(self, charset=None, collation=None):
        super(Database, self).__init__()
        self.charset = charset
        self.collation = collation
