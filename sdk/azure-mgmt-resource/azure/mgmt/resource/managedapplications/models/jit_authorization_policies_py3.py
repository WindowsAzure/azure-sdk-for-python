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


class JitAuthorizationPolicies(Model):
    """The JIT authorization policies.

    All required parameters must be populated in order to send to Azure.

    :param principal_id: Required. The the principal id that will be granted
     JIT access.
    :type principal_id: str
    :param role_definition_id: Required. The role definition id that will be
     granted to the Principal.
    :type role_definition_id: str
    """

    _validation = {
        'principal_id': {'required': True},
        'role_definition_id': {'required': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'PrincipalId', 'type': 'str'},
        'role_definition_id': {'key': 'RoleDefinitionId', 'type': 'str'},
    }

    def __init__(self, *, principal_id: str, role_definition_id: str, **kwargs) -> None:
        super(JitAuthorizationPolicies, self).__init__(**kwargs)
        self.principal_id = principal_id
        self.role_definition_id = role_definition_id
