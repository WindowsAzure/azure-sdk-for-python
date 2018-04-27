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
    """Managed service identity.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param type: Type of managed service identity. Possible values include:
     'SystemAssigned'
    :type type: str or ~azure.mgmt.web.models.ManagedServiceIdentityType
    :ivar tenant_id: Tenant of managed service identity.
    :vartype tenant_id: str
    :ivar principal_id: Principal Id of managed service identity.
    :vartype principal_id: str
    """

    _validation = {
        'tenant_id': {'readonly': True},
        'principal_id': {'readonly': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'principal_id': {'key': 'principalId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ManagedServiceIdentity, self).__init__(**kwargs)
        self.type = kwargs.get('type', None)
        self.tenant_id = None
        self.principal_id = None
