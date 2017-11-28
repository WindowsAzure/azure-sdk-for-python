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

from .resource import Resource


class ArmDisasterRecovery(Resource):
    """Single item in List or Get Alias(Disaster Recovery configuration)
    operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :ivar provisioning_state: Provisioning state of the Alias(Disaster
     Recovery configuration) - possible values 'Accepted' or 'Succeeded' or
     'Failed'. Possible values include: 'Accepted', 'Succeeded', 'Failed'
    :vartype provisioning_state: str or
     ~azure.mgmt.servicebus.models.ProvisioningStateDR
    :param partner_namespace: Primary/Secondary eventhub namespace name, which
     is part of GEO DR pairning
    :type partner_namespace: str
    :ivar role: role of namespace in GEO DR - possible values 'Primary' or
     'PrimaryNotReplicating' or 'Secondary'. Possible values include:
     'Primary', 'PrimaryNotReplicating', 'Secondary'
    :vartype role: str or ~azure.mgmt.servicebus.models.RoleDisasterRecovery
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'role': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'ProvisioningStateDR'},
        'partner_namespace': {'key': 'properties.partnerNamespace', 'type': 'str'},
        'role': {'key': 'properties.role', 'type': 'RoleDisasterRecovery'},
    }

    def __init__(self, partner_namespace=None):
        super(ArmDisasterRecovery, self).__init__()
        self.provisioning_state = None
        self.partner_namespace = partner_namespace
        self.role = None
