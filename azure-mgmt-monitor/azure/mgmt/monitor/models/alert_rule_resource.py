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


class AlertRuleResource(Resource):
    """The alert rule resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param alert_rule_resource_name: the name of the alert rule.
    :type alert_rule_resource_name: str
    :param description: the description of the alert rule that will be
     included in the alert email.
    :type description: str
    :param is_enabled: the flag that indicates whether the alert rule is
     enabled.
    :type is_enabled: bool
    :param condition: the condition that results in the alert rule being
     activated.
    :type condition: ~azure.mgmt.monitor.models.RuleCondition
    :param actions: the array of actions that are performed when the alert
     rule becomes active, and when an alert condition is resolved.
    :type actions: list[~azure.mgmt.monitor.models.RuleAction]
    :ivar last_updated_time: Last time the rule was updated in ISO8601 format.
    :vartype last_updated_time: datetime
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'alert_rule_resource_name': {'required': True},
        'is_enabled': {'required': True},
        'condition': {'required': True},
        'last_updated_time': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'alert_rule_resource_name': {'key': 'properties.name', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'is_enabled': {'key': 'properties.isEnabled', 'type': 'bool'},
        'condition': {'key': 'properties.condition', 'type': 'RuleCondition'},
        'actions': {'key': 'properties.actions', 'type': '[RuleAction]'},
        'last_updated_time': {'key': 'properties.lastUpdatedTime', 'type': 'iso-8601'},
    }

    def __init__(self, location, alert_rule_resource_name, is_enabled, condition, tags=None, description=None, actions=None):
        super(AlertRuleResource, self).__init__(location=location, tags=tags)
        self.alert_rule_resource_name = alert_rule_resource_name
        self.description = description
        self.is_enabled = is_enabled
        self.condition = condition
        self.actions = actions
        self.last_updated_time = None
