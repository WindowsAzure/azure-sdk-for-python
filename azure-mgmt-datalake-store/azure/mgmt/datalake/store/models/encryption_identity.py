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


class EncryptionIdentity(Model):
    """The encryption identity properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar type: The type of encryption being used. Currently the only
     supported type is 'SystemAssigned'. Default value: "SystemAssigned" .
    :vartype type: str
    :ivar principal_id: The principal identifier associated with the
     encryption.
    :vartype principal_id: str
    :ivar tenant_id: The tenant identifier associated with the encryption.
    :vartype tenant_id: str
    """

    _validation = {
        'type': {'required': True, 'constant': True},
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
    }

    type = "SystemAssigned"

    def __init__(self):
        self.principal_id = None
        self.tenant_id = None
