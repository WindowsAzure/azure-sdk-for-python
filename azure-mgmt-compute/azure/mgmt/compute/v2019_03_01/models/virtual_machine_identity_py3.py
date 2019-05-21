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


class VirtualMachineIdentity(Model):
    """Identity for the virtual machine.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar principal_id: The principal id of virtual machine identity. This
     property will only be provided for a system assigned identity.
    :vartype principal_id: str
    :ivar tenant_id: The tenant id associated with the virtual machine. This
     property will only be provided for a system assigned identity.
    :vartype tenant_id: str
    :param type: The type of identity used for the virtual machine. The type
     'SystemAssigned, UserAssigned' includes both an implicitly created
     identity and a set of user assigned identities. The type 'None' will
     remove any identities from the virtual machine. Possible values include:
     'SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned', 'None'
    :type type: str or
     ~azure.mgmt.compute.v2019_03_01.models.ResourceIdentityType
    :param user_assigned_identities: The list of user identities associated
     with the Virtual Machine. The user identity dictionary key references will
     be ARM resource ids in the form:
     '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName}'.
    :type user_assigned_identities: dict[str,
     ~azure.mgmt.compute.v2019_03_01.models.VirtualMachineIdentityUserAssignedIdentitiesValue]
    """

    _validation = {
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'ResourceIdentityType'},
        'user_assigned_identities': {'key': 'userAssignedIdentities', 'type': '{VirtualMachineIdentityUserAssignedIdentitiesValue}'},
    }

    def __init__(self, *, type=None, user_assigned_identities=None, **kwargs) -> None:
        super(VirtualMachineIdentity, self).__init__(**kwargs)
        self.principal_id = None
        self.tenant_id = None
        self.type = type
        self.user_assigned_identities = user_assigned_identities
