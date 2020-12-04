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


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class Error(Model):
    """Object to be thrown in case of an unsuccessful response.

    :param error: Object to be thrown in case of an unsuccessful response
    :type error:
     ~azure.mgmt.authorization.v2020_04_01_preview.models.ErrorError
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorError'},
    }

    def __init__(self, *, error=None, **kwargs) -> None:
        super(Error, self).__init__(**kwargs)
        self.error = error


class ErrorError(Model):
    """Object to be thrown in case of an unsuccessful response.

    :param code: Brief error code
    :type code: str
    :param message: Longer message explaining the details of the error
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, **kwargs) -> None:
        super(ErrorError, self).__init__(**kwargs)
        self.code = code
        self.message = message


class RoleAssignment(Model):
    """Role Assignments.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The role assignment ID.
    :vartype id: str
    :ivar name: The role assignment name.
    :vartype name: str
    :ivar type: The role assignment type.
    :vartype type: str
    :param scope: The role assignment scope.
    :type scope: str
    :param role_definition_id: The role definition ID.
    :type role_definition_id: str
    :param principal_id: The principal ID.
    :type principal_id: str
    :param principal_type: The principal type of the assigned principal ID.
     Possible values include: 'User', 'Group', 'ServicePrincipal', 'Unknown',
     'DirectoryRoleTemplate', 'ForeignGroup', 'Application', 'MSI',
     'DirectoryObjectOrGroup', 'Everyone'
    :type principal_type: str or
     ~azure.mgmt.authorization.v2020_04_01_preview.models.PrincipalType
    :param can_delegate: The Delegation flag for the role assignment
    :type can_delegate: bool
    :param description: Description of role assignment
    :type description: str
    :param condition: The conditions on the role assignment. This limits the
     resources it can be assigned to. e.g.:
     @Resource[Microsoft.Storage/storageAccounts/blobServices/containers:ContainerName]
     StringEqualsIgnoreCase 'foo_storage_container'
    :type condition: str
    :param condition_version: Version of the condition. Currently accepted
     value is '2.0'
    :type condition_version: str
    :param created_on: Time it was created
    :type created_on: datetime
    :param updated_on: Time it was updated
    :type updated_on: datetime
    :param created_by: Id of the user who created the assignment
    :type created_by: str
    :param updated_by: Id of the user who updated the assignment
    :type updated_by: str
    :param delegated_managed_identity_resource_id: Id of the delegated managed
     identity resource
    :type delegated_managed_identity_resource_id: str
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
        'scope': {'key': 'properties.scope', 'type': 'str'},
        'role_definition_id': {'key': 'properties.roleDefinitionId', 'type': 'str'},
        'principal_id': {'key': 'properties.principalId', 'type': 'str'},
        'principal_type': {'key': 'properties.principalType', 'type': 'str'},
        'can_delegate': {'key': 'properties.canDelegate', 'type': 'bool'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'condition': {'key': 'properties.condition', 'type': 'str'},
        'condition_version': {'key': 'properties.conditionVersion', 'type': 'str'},
        'created_on': {'key': 'properties.createdOn', 'type': 'iso-8601'},
        'updated_on': {'key': 'properties.updatedOn', 'type': 'iso-8601'},
        'created_by': {'key': 'properties.createdBy', 'type': 'str'},
        'updated_by': {'key': 'properties.updatedBy', 'type': 'str'},
        'delegated_managed_identity_resource_id': {'key': 'properties.delegatedManagedIdentityResourceId', 'type': 'str'},
    }

    def __init__(self, *, scope: str=None, role_definition_id: str=None, principal_id: str=None, principal_type=None, can_delegate: bool=None, description: str=None, condition: str=None, condition_version: str=None, created_on=None, updated_on=None, created_by: str=None, updated_by: str=None, delegated_managed_identity_resource_id: str=None, **kwargs) -> None:
        super(RoleAssignment, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.scope = scope
        self.role_definition_id = role_definition_id
        self.principal_id = principal_id
        self.principal_type = principal_type
        self.can_delegate = can_delegate
        self.description = description
        self.condition = condition
        self.condition_version = condition_version
        self.created_on = created_on
        self.updated_on = updated_on
        self.created_by = created_by
        self.updated_by = updated_by
        self.delegated_managed_identity_resource_id = delegated_managed_identity_resource_id


class RoleAssignmentCreateParameters(Model):
    """Role assignment create parameters.

    All required parameters must be populated in order to send to Azure.

    :param role_definition_id: Required. The role definition ID used in the
     role assignment.
    :type role_definition_id: str
    :param principal_id: Required. The principal ID assigned to the role. This
     maps to the ID inside the Active Directory. It can point to a user,
     service principal, or security group.
    :type principal_id: str
    :param principal_type: The principal type of the assigned principal ID.
     Possible values include: 'User', 'Group', 'ServicePrincipal', 'Unknown',
     'DirectoryRoleTemplate', 'ForeignGroup', 'Application', 'MSI',
     'DirectoryObjectOrGroup', 'Everyone'
    :type principal_type: str or
     ~azure.mgmt.authorization.v2020_04_01_preview.models.PrincipalType
    :param can_delegate: The delegation flag used for creating a role
     assignment
    :type can_delegate: bool
    :param description: Description of role assignment
    :type description: str
    :param condition: The conditions on the role assignment. This limits the
     resources it can be assigned to. e.g.:
     @Resource[Microsoft.Storage/storageAccounts/blobServices/containers:ContainerName]
     StringEqualsIgnoreCase 'foo_storage_container'
    :type condition: str
    :param condition_version: Version of the condition. Currently accepted
     value is '2.0'
    :type condition_version: str
    """

    _validation = {
        'role_definition_id': {'required': True},
        'principal_id': {'required': True},
    }

    _attribute_map = {
        'role_definition_id': {'key': 'properties.roleDefinitionId', 'type': 'str'},
        'principal_id': {'key': 'properties.principalId', 'type': 'str'},
        'principal_type': {'key': 'properties.principalType', 'type': 'str'},
        'can_delegate': {'key': 'properties.canDelegate', 'type': 'bool'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'condition': {'key': 'properties.condition', 'type': 'str'},
        'condition_version': {'key': 'properties.conditionVersion', 'type': 'str'},
    }

    def __init__(self, *, role_definition_id: str, principal_id: str, principal_type=None, can_delegate: bool=None, description: str=None, condition: str=None, condition_version: str=None, **kwargs) -> None:
        super(RoleAssignmentCreateParameters, self).__init__(**kwargs)
        self.role_definition_id = role_definition_id
        self.principal_id = principal_id
        self.principal_type = principal_type
        self.can_delegate = can_delegate
        self.description = description
        self.condition = condition
        self.condition_version = condition_version


class RoleAssignmentFilter(Model):
    """Role Assignments filter.

    :param principal_id: Returns role assignment of the specific principal.
    :type principal_id: str
    :param can_delegate: The Delegation flag for the role assignment
    :type can_delegate: bool
    """

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'can_delegate': {'key': 'canDelegate', 'type': 'bool'},
    }

    def __init__(self, *, principal_id: str=None, can_delegate: bool=None, **kwargs) -> None:
        super(RoleAssignmentFilter, self).__init__(**kwargs)
        self.principal_id = principal_id
        self.can_delegate = can_delegate
