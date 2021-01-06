# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import List, Optional

import msrest.serialization


class Permission(msrest.serialization.Model):
    """Role definition permissions.

    :param actions: Allowed actions.
    :type actions: list[str]
    :param not_actions: Denied actions.
    :type not_actions: list[str]
    :param data_actions: Allowed Data actions.
    :type data_actions: list[str]
    :param not_data_actions: Denied Data actions.
    :type not_data_actions: list[str]
    """

    _attribute_map = {
        'actions': {'key': 'actions', 'type': '[str]'},
        'not_actions': {'key': 'notActions', 'type': '[str]'},
        'data_actions': {'key': 'dataActions', 'type': '[str]'},
        'not_data_actions': {'key': 'notDataActions', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        actions: Optional[List[str]] = None,
        not_actions: Optional[List[str]] = None,
        data_actions: Optional[List[str]] = None,
        not_data_actions: Optional[List[str]] = None,
        **kwargs
    ):
        super(Permission, self).__init__(**kwargs)
        self.actions = actions
        self.not_actions = not_actions
        self.data_actions = data_actions
        self.not_data_actions = not_data_actions


class PermissionGetResult(msrest.serialization.Model):
    """Permissions information.

    :param value: An array of permissions.
    :type value: list[~azure.mgmt.authorization.v2018_01_01_preview.models.Permission]
    :param next_link: The URL to use for getting the next set of results.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Permission]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["Permission"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(PermissionGetResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class ProviderOperation(msrest.serialization.Model):
    """Operation.

    :param name: The operation name.
    :type name: str
    :param display_name: The operation display name.
    :type display_name: str
    :param description: The operation description.
    :type description: str
    :param origin: The operation origin.
    :type origin: str
    :param properties: The operation properties.
    :type properties: object
    :param is_data_action: The dataAction flag to specify the operation type.
    :type is_data_action: bool
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'origin': {'key': 'origin', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'object'},
        'is_data_action': {'key': 'isDataAction', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        origin: Optional[str] = None,
        properties: Optional[object] = None,
        is_data_action: Optional[bool] = None,
        **kwargs
    ):
        super(ProviderOperation, self).__init__(**kwargs)
        self.name = name
        self.display_name = display_name
        self.description = description
        self.origin = origin
        self.properties = properties
        self.is_data_action = is_data_action


class ProviderOperationsMetadata(msrest.serialization.Model):
    """Provider Operations metadata.

    :param id: The provider id.
    :type id: str
    :param name: The provider name.
    :type name: str
    :param type: The provider type.
    :type type: str
    :param display_name: The provider display name.
    :type display_name: str
    :param resource_types: The provider resource types.
    :type resource_types: list[~azure.mgmt.authorization.v2018_01_01_preview.models.ResourceType]
    :param operations: The provider operations.
    :type operations: list[~azure.mgmt.authorization.v2018_01_01_preview.models.ProviderOperation]
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'resource_types': {'key': 'resourceTypes', 'type': '[ResourceType]'},
        'operations': {'key': 'operations', 'type': '[ProviderOperation]'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        name: Optional[str] = None,
        type: Optional[str] = None,
        display_name: Optional[str] = None,
        resource_types: Optional[List["ResourceType"]] = None,
        operations: Optional[List["ProviderOperation"]] = None,
        **kwargs
    ):
        super(ProviderOperationsMetadata, self).__init__(**kwargs)
        self.id = id
        self.name = name
        self.type = type
        self.display_name = display_name
        self.resource_types = resource_types
        self.operations = operations


class ProviderOperationsMetadataListResult(msrest.serialization.Model):
    """Provider operations metadata list.

    :param value: The list of providers.
    :type value:
     list[~azure.mgmt.authorization.v2018_01_01_preview.models.ProviderOperationsMetadata]
    :param next_link: The URL to use for getting the next set of results.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ProviderOperationsMetadata]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["ProviderOperationsMetadata"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(ProviderOperationsMetadataListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class ResourceType(msrest.serialization.Model):
    """Resource Type.

    :param name: The resource type name.
    :type name: str
    :param display_name: The resource type display name.
    :type display_name: str
    :param operations: The resource type operations.
    :type operations: list[~azure.mgmt.authorization.v2018_01_01_preview.models.ProviderOperation]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'operations': {'key': 'operations', 'type': '[ProviderOperation]'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        display_name: Optional[str] = None,
        operations: Optional[List["ProviderOperation"]] = None,
        **kwargs
    ):
        super(ResourceType, self).__init__(**kwargs)
        self.name = name
        self.display_name = display_name
        self.operations = operations


class RoleAssignment(msrest.serialization.Model):
    """Role Assignments.

    Variables are only populated by the server, and will be ignored when sending a request.

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
    :param can_delegate: The Delegation flag for the role assignment.
    :type can_delegate: bool
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
        'can_delegate': {'key': 'properties.canDelegate', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        scope: Optional[str] = None,
        role_definition_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        can_delegate: Optional[bool] = None,
        **kwargs
    ):
        super(RoleAssignment, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.scope = scope
        self.role_definition_id = role_definition_id
        self.principal_id = principal_id
        self.can_delegate = can_delegate


class RoleAssignmentCreateParameters(msrest.serialization.Model):
    """Role assignment create parameters.

    All required parameters must be populated in order to send to Azure.

    :param role_definition_id: Required. The role definition ID used in the role assignment.
    :type role_definition_id: str
    :param principal_id: Required. The principal ID assigned to the role. This maps to the ID
     inside the Active Directory. It can point to a user, service principal, or security group.
    :type principal_id: str
    :param can_delegate: The delegation flag used for creating a role assignment.
    :type can_delegate: bool
    """

    _validation = {
        'role_definition_id': {'required': True},
        'principal_id': {'required': True},
    }

    _attribute_map = {
        'role_definition_id': {'key': 'properties.roleDefinitionId', 'type': 'str'},
        'principal_id': {'key': 'properties.principalId', 'type': 'str'},
        'can_delegate': {'key': 'properties.canDelegate', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        role_definition_id: str,
        principal_id: str,
        can_delegate: Optional[bool] = None,
        **kwargs
    ):
        super(RoleAssignmentCreateParameters, self).__init__(**kwargs)
        self.role_definition_id = role_definition_id
        self.principal_id = principal_id
        self.can_delegate = can_delegate


class RoleAssignmentFilter(msrest.serialization.Model):
    """Role Assignments filter.

    :param principal_id: Returns role assignment of the specific principal.
    :type principal_id: str
    :param can_delegate: The Delegation flag for the role assignment.
    :type can_delegate: bool
    """

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'can_delegate': {'key': 'canDelegate', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        principal_id: Optional[str] = None,
        can_delegate: Optional[bool] = None,
        **kwargs
    ):
        super(RoleAssignmentFilter, self).__init__(**kwargs)
        self.principal_id = principal_id
        self.can_delegate = can_delegate


class RoleAssignmentListResult(msrest.serialization.Model):
    """Role assignment list operation result.

    :param value: Role assignment list.
    :type value: list[~azure.mgmt.authorization.v2018_01_01_preview.models.RoleAssignment]
    :param next_link: The URL to use for getting the next set of results.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[RoleAssignment]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["RoleAssignment"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(RoleAssignmentListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class RoleDefinition(msrest.serialization.Model):
    """Role definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The role definition ID.
    :vartype id: str
    :ivar name: The role definition name.
    :vartype name: str
    :ivar type: The role definition type.
    :vartype type: str
    :param role_name: The role name.
    :type role_name: str
    :param description: The role definition description.
    :type description: str
    :param role_type: The role type.
    :type role_type: str
    :param permissions: Role definition permissions.
    :type permissions: list[~azure.mgmt.authorization.v2018_01_01_preview.models.Permission]
    :param assignable_scopes: Role definition assignable scopes.
    :type assignable_scopes: list[str]
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
        'role_name': {'key': 'properties.roleName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'role_type': {'key': 'properties.type', 'type': 'str'},
        'permissions': {'key': 'properties.permissions', 'type': '[Permission]'},
        'assignable_scopes': {'key': 'properties.assignableScopes', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        role_name: Optional[str] = None,
        description: Optional[str] = None,
        role_type: Optional[str] = None,
        permissions: Optional[List["Permission"]] = None,
        assignable_scopes: Optional[List[str]] = None,
        **kwargs
    ):
        super(RoleDefinition, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.role_name = role_name
        self.description = description
        self.role_type = role_type
        self.permissions = permissions
        self.assignable_scopes = assignable_scopes


class RoleDefinitionFilter(msrest.serialization.Model):
    """Role Definitions filter.

    :param role_name: Returns role definition with the specific name.
    :type role_name: str
    :param type: Returns role definition with the specific type.
    :type type: str
    """

    _attribute_map = {
        'role_name': {'key': 'roleName', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        role_name: Optional[str] = None,
        type: Optional[str] = None,
        **kwargs
    ):
        super(RoleDefinitionFilter, self).__init__(**kwargs)
        self.role_name = role_name
        self.type = type


class RoleDefinitionListResult(msrest.serialization.Model):
    """Role definition list operation result.

    :param value: Role definition list.
    :type value: list[~azure.mgmt.authorization.v2018_01_01_preview.models.RoleDefinition]
    :param next_link: The URL to use for getting the next set of results.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[RoleDefinition]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["RoleDefinition"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(RoleDefinitionListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link
