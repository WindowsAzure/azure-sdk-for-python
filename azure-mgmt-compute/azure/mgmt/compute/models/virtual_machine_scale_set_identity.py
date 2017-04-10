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


class VirtualMachineScaleSetIdentity(Model):
    """Identity for the virtual machine scale set.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar principal_id: The principal id of virtual machine scale set
     identity.
    :vartype principal_id: str
    :ivar tenant_id: The tenant id associated with the virtual machine scale
     set.
    :vartype tenant_id: str
    :param type: The type of identity used for the virtual machine scale set.
     Currently, the only supported type is 'SystemAssigned', which implicitly
     creates an identity. Possible values include: 'SystemAssigned'
    :type type: str or :class:`ResourceIdentityType
     <azure.mgmt.compute.models.ResourceIdentityType>`
    """

    _validation = {
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'ResourceIdentityType'},
    }

    def __init__(self, type=None):
        self.principal_id = None
        self.tenant_id = None
        self.type = type
