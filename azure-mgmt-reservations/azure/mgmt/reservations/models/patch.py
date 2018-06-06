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
    :param instance_flexibility: Possible values include: 'On', 'Off',
     'NotSupported'
    :type instance_flexibility: str or ~azure.mgmt.reservations.models.enum
    """

    _attribute_map = {
        'applied_scope_type': {'key': 'properties.appliedScopeType', 'type': 'str'},
        'applied_scopes': {'key': 'properties.appliedScopes', 'type': '[str]'},
        'instance_flexibility': {'key': 'properties.instanceFlexibility', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Patch, self).__init__(**kwargs)
        self.applied_scope_type = kwargs.get('applied_scope_type', None)
        self.applied_scopes = kwargs.get('applied_scopes', None)
        self.instance_flexibility = kwargs.get('instance_flexibility', None)
