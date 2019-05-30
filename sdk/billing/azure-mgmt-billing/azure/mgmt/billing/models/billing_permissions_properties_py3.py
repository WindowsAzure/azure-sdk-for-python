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


class BillingPermissionsProperties(Model):
    """The set of allowed action and not allowed actions a caller has on a billing
    account.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar actions: The set of actions that the caller is allowed to do
    :vartype actions: list[str]
    :ivar not_actions: The set of actions the caller is not allowed to do
    :vartype not_actions: list[str]
    """

    _validation = {
        'actions': {'readonly': True},
        'not_actions': {'readonly': True},
    }

    _attribute_map = {
        'actions': {'key': 'actions', 'type': '[str]'},
        'not_actions': {'key': 'notActions', 'type': '[str]'},
    }

    def __init__(self, **kwargs) -> None:
        super(BillingPermissionsProperties, self).__init__(**kwargs)
        self.actions = None
        self.not_actions = None
