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


class Identity(Model):
    """Identity for the resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar principal_id: The principal ID of resource identity.
    :vartype principal_id: str
    :ivar tenant_id: The tenant ID of resource.
    :vartype tenant_id: str
    :param type: The identity type. Possible values include: 'SystemAssigned'
    :type type: str or
     ~azure.mgmt.resource.resources.v2016_09_01.models.ResourceIdentityType
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

    def __init__(self, **kwargs):
        super(Identity, self).__init__(**kwargs)
        self.principal_id = None
        self.tenant_id = None
        self.type = kwargs.get('type', None)
