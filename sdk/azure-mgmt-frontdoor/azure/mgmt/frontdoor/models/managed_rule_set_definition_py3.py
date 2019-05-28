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

from .resource_py3 import Resource


class ManagedRuleSetDefinition(Resource):
    """Describes the a managed rule set definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :ivar provisioning_state: Provisioning state of the managed rule set.
    :vartype provisioning_state: str
    :ivar rule_set_type: Type of the managed rule set.
    :vartype rule_set_type: str
    :ivar rule_set_version: Version of the managed rule set type.
    :vartype rule_set_version: str
    :ivar rule_groups: Rule groups of the managed rule set.
    :vartype rule_groups:
     list[~azure.mgmt.frontdoor.models.ManagedRuleGroupDefinition]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'rule_set_type': {'readonly': True},
        'rule_set_version': {'readonly': True},
        'rule_groups': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'rule_set_type': {'key': 'properties.ruleSetType', 'type': 'str'},
        'rule_set_version': {'key': 'properties.ruleSetVersion', 'type': 'str'},
        'rule_groups': {'key': 'properties.ruleGroups', 'type': '[ManagedRuleGroupDefinition]'},
    }

    def __init__(self, *, location: str=None, tags=None, **kwargs) -> None:
        super(ManagedRuleSetDefinition, self).__init__(location=location, tags=tags, **kwargs)
        self.provisioning_state = None
        self.rule_set_type = None
        self.rule_set_version = None
        self.rule_groups = None
