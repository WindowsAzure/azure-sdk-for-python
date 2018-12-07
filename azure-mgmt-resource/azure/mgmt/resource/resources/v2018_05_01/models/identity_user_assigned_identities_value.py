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


class IdentityUserAssignedIdentitiesValue(Model):
    """IdentityUserAssignedIdentitiesValue.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar principal_id: The principal id of user assigned identity.
    :vartype principal_id: str
    :ivar client_id: The client id of user assigned identity.
    :vartype client_id: str
    """

    _validation = {
        'principal_id': {'readonly': True},
        'client_id': {'readonly': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'client_id': {'key': 'clientId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(IdentityUserAssignedIdentitiesValue, self).__init__(**kwargs)
        self.principal_id = None
        self.client_id = None
