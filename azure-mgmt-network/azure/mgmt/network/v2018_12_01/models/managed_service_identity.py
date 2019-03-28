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


class ManagedServiceIdentity(Model):
    """Identity for the resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar principal_id: The principal id of the system assigned identity. This
     property will only be provided for a system assigned identity.
    :vartype principal_id: str
    :ivar tenant_id: The tenant id of the system assigned identity. This
     property will only be provided for a system assigned identity.
    :vartype tenant_id: str
    :param type: The type of identity used for the resource. The type
     'SystemAssigned, UserAssigned' includes both an implicitly created
     identity and a set of user assigned identities. The type 'None' will
     remove any identities from the virtual machine. Possible values include:
     'SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned', 'None'
    :type type: str or
     ~azure.mgmt.network.v2018_12_01.models.ResourceIdentityType
    :param user_assigned_identities: The list of user identities associated
     with resource. The user identity dictionary key references will be ARM
     resource ids in the form:
     '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName}'.
    :type user_assigned_identities: dict[str,
     ~azure.mgmt.network.v2018_12_01.models.ManagedServiceIdentityUserAssignedIdentitiesValue]
    """

    _validation = {
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'ResourceIdentityType'},
        'user_assigned_identities': {'key': 'userAssignedIdentities', 'type': '{ManagedServiceIdentityUserAssignedIdentitiesValue}'},
    }

    def __init__(self, **kwargs):
        super(ManagedServiceIdentity, self).__init__(**kwargs)
        self.principal_id = None
        self.tenant_id = None
        self.type = kwargs.get('type', None)
        self.user_assigned_identities = kwargs.get('user_assigned_identities', None)
