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
    :param can_delegate: The delgation flag used for creating a role
     assignment
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

    def __init__(self, *, role_definition_id: str, principal_id: str, can_delegate: bool=None, **kwargs) -> None:
        super(RoleAssignmentCreateParameters, self).__init__(**kwargs)
        self.role_definition_id = role_definition_id
        self.principal_id = principal_id
        self.can_delegate = can_delegate
