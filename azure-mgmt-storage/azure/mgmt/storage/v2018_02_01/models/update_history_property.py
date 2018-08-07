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


class UpdateHistoryProperty(Model):
    """An update history of the ImmutabilityPolicy of a blob container.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar update: The ImmutabilityPolicy update type of a blob container,
     possible values include: put, lock and extend. Possible values include:
     'put', 'lock', 'extend'
    :vartype update: str or
     ~azure.mgmt.storage.v2018_02_01.models.ImmutabilityPolicyUpdateType
    :ivar immutability_period_since_creation_in_days: The immutability period
     for the blobs in the container since the policy creation, in days.
    :vartype immutability_period_since_creation_in_days: int
    :ivar timestamp: Returns the date and time the ImmutabilityPolicy was
     updated.
    :vartype timestamp: datetime
    :ivar object_identifier: Returns the Object ID of the user who updated the
     ImmutabilityPolicy.
    :vartype object_identifier: str
    :ivar tenant_id: Returns the Tenant ID that issued the token for the user
     who updated the ImmutabilityPolicy.
    :vartype tenant_id: str
    :ivar upn: Returns the User Principal Name of the user who updated the
     ImmutabilityPolicy.
    :vartype upn: str
    """

    _validation = {
        'update': {'readonly': True},
        'immutability_period_since_creation_in_days': {'readonly': True},
        'timestamp': {'readonly': True},
        'object_identifier': {'readonly': True},
        'tenant_id': {'readonly': True},
        'upn': {'readonly': True},
    }

    _attribute_map = {
        'update': {'key': 'update', 'type': 'str'},
        'immutability_period_since_creation_in_days': {'key': 'immutabilityPeriodSinceCreationInDays', 'type': 'int'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'object_identifier': {'key': 'objectIdentifier', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'upn': {'key': 'upn', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(UpdateHistoryProperty, self).__init__(**kwargs)
        self.update = None
        self.immutability_period_since_creation_in_days = None
        self.timestamp = None
        self.object_identifier = None
        self.tenant_id = None
        self.upn = None
