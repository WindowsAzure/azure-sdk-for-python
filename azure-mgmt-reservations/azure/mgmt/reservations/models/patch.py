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


class Patch(Model):
    """Patch.

    :param applied_scope_type: Possible values include: 'Single', 'Shared'
    :type applied_scope_type: str or ~azure.mgmt.reservations.models.enum
    :param applied_scopes:
    :type applied_scopes: list[str]
    """

    _attribute_map = {
        'applied_scope_type': {'key': 'properties.appliedScopeType', 'type': 'str'},
        'applied_scopes': {'key': 'properties.appliedScopes', 'type': '[str]'},
    }

    def __init__(self, applied_scope_type=None, applied_scopes=None):
        super(Patch, self).__init__()
        self.applied_scope_type = applied_scope_type
        self.applied_scopes = applied_scopes
