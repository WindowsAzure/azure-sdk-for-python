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


class ActivityLogAlertResource(Resource):
    """An activity log alert resource.

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
    :type tags: dict
    :param scopes: A list of resourceIds that will be used as prefixes. The
     alert will only apply to activityLogs with resourceIds that fall under one
     of these prefixes. This list must include at least one item.
    :type scopes: list of str
    :param enabled: Indicates whether this activity log alert is enabled. If
     an activity log alert is not enabled, then none of its actions will be
     activated. Default value: True .
    :type enabled: bool
    :param condition: The condition that will cause this alert to activate.
    :type condition: :class:`ActivityLogAlertAllOfCondition
     <azure.mgmt.monitor.models.ActivityLogAlertAllOfCondition>`
    :param actions: The actions that will activate when the condition is met.
    :type actions: :class:`ActivityLogAlertActionList
     <azure.mgmt.monitor.models.ActivityLogAlertActionList>`
    :param description: A description of this activity log alert.
    :type description: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'scopes': {'required': True},
        'condition': {'required': True},
        'actions': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'scopes': {'key': 'properties.scopes', 'type': '[str]'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'condition': {'key': 'properties.condition', 'type': 'ActivityLogAlertAllOfCondition'},
        'actions': {'key': 'properties.actions', 'type': 'ActivityLogAlertActionList'},
        'description': {'key': 'properties.description', 'type': 'str'},
    }

    def __init__(self, location, scopes, condition, actions, tags=None, enabled=True, description=None):
        super(ActivityLogAlertResource, self).__init__(location=location, tags=tags)
        self.scopes = scopes
        self.enabled = enabled
        self.condition = condition
        self.actions = actions
        self.description = description
