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


class ManagementLockObject(Model):
    """The lock information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param level: Required. The level of the lock. Possible values are:
     NotSpecified, CanNotDelete, ReadOnly. CanNotDelete means authorized users
     are able to read and modify the resources, but not delete. ReadOnly means
     authorized users can only read from a resource, but they can't modify or
     delete it. Possible values include: 'NotSpecified', 'CanNotDelete',
     'ReadOnly'
    :type level: str or
     ~azure.mgmt.resource.locks.v2016_09_01.models.LockLevel
    :param notes: Notes about the lock. Maximum of 512 characters.
    :type notes: str
    :param owners: The owners of the lock.
    :type owners:
     list[~azure.mgmt.resource.locks.v2016_09_01.models.ManagementLockOwner]
    :ivar id: The resource ID of the lock.
    :vartype id: str
    :ivar type: The resource type of the lock - Microsoft.Authorization/locks.
    :vartype type: str
    :ivar name: The name of the lock.
    :vartype name: str
    """

    _validation = {
        'level': {'required': True},
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'level': {'key': 'properties.level', 'type': 'str'},
        'notes': {'key': 'properties.notes', 'type': 'str'},
        'owners': {'key': 'properties.owners', 'type': '[ManagementLockOwner]'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ManagementLockObject, self).__init__(**kwargs)
        self.level = kwargs.get('level', None)
        self.notes = kwargs.get('notes', None)
        self.owners = kwargs.get('owners', None)
        self.id = None
        self.type = None
        self.name = None
