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


class EnrollmentPolicies(Model):
    """The attributes associated with legacy enrollment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar account_owner_view_charges: The accountOwnerViewCharges flag for
     Enrollment
    :vartype account_owner_view_charges: bool
    :ivar department_admin_view_charges: The departmentAdminViewCharges flag
     for Enrollment
    :vartype department_admin_view_charges: bool
    :ivar marketplaces_enabled: The marketplaces flag for Enrollment
    :vartype marketplaces_enabled: bool
    :ivar reserved_instances_enabled: The reserved instances flag for
     Enrollment
    :vartype reserved_instances_enabled: bool
    """

    _validation = {
        'account_owner_view_charges': {'readonly': True},
        'department_admin_view_charges': {'readonly': True},
        'marketplaces_enabled': {'readonly': True},
        'reserved_instances_enabled': {'readonly': True},
    }

    _attribute_map = {
        'account_owner_view_charges': {'key': 'accountOwnerViewCharges', 'type': 'bool'},
        'department_admin_view_charges': {'key': 'departmentAdminViewCharges', 'type': 'bool'},
        'marketplaces_enabled': {'key': 'marketplacesEnabled', 'type': 'bool'},
        'reserved_instances_enabled': {'key': 'reservedInstancesEnabled', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(EnrollmentPolicies, self).__init__(**kwargs)
        self.account_owner_view_charges = None
        self.department_admin_view_charges = None
        self.marketplaces_enabled = None
        self.reserved_instances_enabled = None
