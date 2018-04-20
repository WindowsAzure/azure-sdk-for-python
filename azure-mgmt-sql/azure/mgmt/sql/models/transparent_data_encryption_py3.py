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


class TransparentDataEncryption(ProxyResource):
    """Represents a database transparent data encryption configuration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar location: Resource location.
    :vartype location: str
    :param status: The status of the database transparent data encryption.
     Possible values include: 'Enabled', 'Disabled'
    :type status: str or
     ~azure.mgmt.sql.models.TransparentDataEncryptionStatus
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'TransparentDataEncryptionStatus'},
    }

    def __init__(self, *, status=None, **kwargs) -> None:
        super(TransparentDataEncryption, self).__init__(**kwargs)
        self.location = None
        self.status = status
