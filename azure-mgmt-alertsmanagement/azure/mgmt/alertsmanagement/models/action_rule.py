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

from .managed_resource import ManagedResource


class ActionRule(ManagedResource):
    """Action rule object containing target scope, conditions and suppression
    logic.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar type: Azure resource type
    :vartype type: str
    :ivar name: Azure resource name
    :vartype name: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param scope: scope on which action rule will apply
    :type scope: ~azure.mgmt.alertsmanagement.models.Scope
    :param conditions: conditions on which alerts will be filtered
    :type conditions: ~azure.mgmt.alertsmanagement.models.Conditions
    :param description: Description of action rule
    :type description: str
    :ivar created_at: Creation time of action rule. Date-Time in ISO-8601
     format.
    :vartype created_at: datetime
    :ivar last_modified_at: Last updated time of action rule. Date-Time in
     ISO-8601 format.
    :vartype last_modified_at: datetime
    :ivar created_by: Created by user name.
    :vartype created_by: str
    :ivar last_modified_by: Last modified by user name.
    :vartype last_modified_by: str
    :param status: Indicates if the given action rule is enabled or disabled.
     Possible values include: 'Enabled', 'Disabled'
    :type status: str or ~azure.mgmt.alertsmanagement.models.ActionRuleStatus
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'location': {'required': True},
        'created_at': {'readonly': True},
        'last_modified_at': {'readonly': True},
        'created_by': {'readonly': True},
        'last_modified_by': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'scope': {'key': 'properties.scope', 'type': 'Scope'},
        'conditions': {'key': 'properties.conditions', 'type': 'Conditions'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'last_modified_at': {'key': 'properties.lastModifiedAt', 'type': 'iso-8601'},
        'created_by': {'key': 'properties.createdBy', 'type': 'str'},
        'last_modified_by': {'key': 'properties.lastModifiedBy', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ActionRule, self).__init__(**kwargs)
        self.scope = kwargs.get('scope', None)
        self.conditions = kwargs.get('conditions', None)
        self.description = kwargs.get('description', None)
        self.created_at = None
        self.last_modified_at = None
        self.created_by = None
        self.last_modified_by = None
        self.status = kwargs.get('status', None)
