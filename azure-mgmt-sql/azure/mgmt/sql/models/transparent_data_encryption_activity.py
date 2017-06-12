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

from .sub_resource import SubResource


class TransparentDataEncryptionActivity(SubResource):
    """Represents a database transparent data encryption Scan.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Resource name
    :vartype name: str
    :ivar id: The resource ID.
    :vartype id: str
    :ivar status: The status of the database. Possible values include:
     'Encrypting', 'Decrypting'
    :vartype status: str or :class:`TransparentDataEncryptionActivityStatus
     <azure.mgmt.sql.models.TransparentDataEncryptionActivityStatus>`
    :ivar percent_complete: The percent complete of the transparent data
     encryption scan for a database.
    :vartype percent_complete: float
    """

    _validation = {
        'name': {'readonly': True},
        'id': {'readonly': True},
        'status': {'readonly': True},
        'percent_complete': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'percent_complete': {'key': 'properties.percentComplete', 'type': 'float'},
    }

    def __init__(self):
        super(TransparentDataEncryptionActivity, self).__init__()
        self.status = None
        self.percent_complete = None
