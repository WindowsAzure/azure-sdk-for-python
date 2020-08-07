# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import msrest.serialization


class ManagementLockListResult(msrest.serialization.Model):
    """The list of locks.

    :param value: The list of locks.
    :type value: list[~azure.mgmt.resource.locks.v2016_09_01.models.ManagementLockObject]
    :param next_link: The URL to use for getting the next set of results.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ManagementLockObject]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ManagementLockListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


class ManagementLockObject(msrest.serialization.Model):
    """The lock information.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource ID of the lock.
    :vartype id: str
    :ivar type: The resource type of the lock - Microsoft.Authorization/locks.
    :vartype type: str
    :ivar name: The name of the lock.
    :vartype name: str
    :param level: Required. The level of the lock. Possible values are: NotSpecified, CanNotDelete,
     ReadOnly. CanNotDelete means authorized users are able to read and modify the resources, but
     not delete. ReadOnly means authorized users can only read from a resource, but they can't
     modify or delete it. Possible values include: "NotSpecified", "CanNotDelete", "ReadOnly".
    :type level: str or ~azure.mgmt.resource.locks.v2016_09_01.models.LockLevel
    :param notes: Notes about the lock. Maximum of 512 characters.
    :type notes: str
    :param owners: The owners of the lock.
    :type owners: list[~azure.mgmt.resource.locks.v2016_09_01.models.ManagementLockOwner]
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'level': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'level': {'key': 'properties.level', 'type': 'str'},
        'notes': {'key': 'properties.notes', 'type': 'str'},
        'owners': {'key': 'properties.owners', 'type': '[ManagementLockOwner]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ManagementLockObject, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.name = None
        self.level = kwargs['level']
        self.notes = kwargs.get('notes', None)
        self.owners = kwargs.get('owners', None)


class ManagementLockOwner(msrest.serialization.Model):
    """Lock owner properties.

    :param application_id: The application ID of the lock owner.
    :type application_id: str
    """

    _attribute_map = {
        'application_id': {'key': 'applicationId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ManagementLockOwner, self).__init__(**kwargs)
        self.application_id = kwargs.get('application_id', None)


class Operation(msrest.serialization.Model):
    """Microsoft.Authorization operation.

    :param name: Operation name: {provider}/{resource}/{operation}.
    :type name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.resource.locks.v2016_09_01.models.OperationDisplay
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Operation, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display = kwargs.get('display', None)


class OperationDisplay(msrest.serialization.Model):
    """The object that represents the operation.

    :param provider: Service provider: Microsoft.Authorization.
    :type provider: str
    :param resource: Resource on which the operation is performed: Profile, endpoint, etc.
    :type resource: str
    :param operation: Operation type: Read, write, delete, etc.
    :type operation: str
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
        self.operation = kwargs.get('operation', None)


class OperationListResult(msrest.serialization.Model):
    """Result of the request to list Microsoft.Authorization operations. It contains a list of operations and a URL link to get the next set of results.

    :param value: List of Microsoft.Authorization operations.
    :type value: list[~azure.mgmt.resource.locks.v2016_09_01.models.Operation]
    :param next_link: URL to get the next set of operation list results if there are any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)
