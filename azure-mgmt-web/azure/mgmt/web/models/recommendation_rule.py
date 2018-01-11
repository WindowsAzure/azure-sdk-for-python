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


class RecommendationRule(Model):
    """Represents a recommendation rule that the recommendation engine can
    perform.

    :param name: Unique name of the rule.
    :type name: str
    :param display_name: UI friendly name of the rule.
    :type display_name: str
    :param message: Localized name of the rule (Good for UI).
    :type message: str
    :param recommendation_id: Recommendation ID of an associated
     recommendation object tied to the rule, if exists.
     If such an object doesn't exist, it is set to null.
    :type recommendation_id: str
    :param description: Localized detailed description of the rule.
    :type description: str
    :param action_name: Name of action that is recommended by this rule in
     string.
    :type action_name: str
    :param level: Level of impact indicating how critical this rule is.
     Possible values include: 'Critical', 'Warning', 'Information',
     'NonUrgentSuggestion'
    :type level: str or ~azure.mgmt.web.models.NotificationLevel
    :param channels: List of available channels that this rule applies.
     Possible values include: 'Notification', 'Api', 'Email', 'Webhook', 'All'
    :type channels: str or ~azure.mgmt.web.models.Channels
    :param tags: An array of category tags that the rule contains.
    :type tags: list[str]
    :param is_dynamic: True if this is associated with a dynamically added
     rule
    :type is_dynamic: bool
    :param extension_name: Extension name of the portal if exists. Applicable
     to dynamic rule only.
    :type extension_name: str
    :param blade_name: Deep link to a blade on the portal. Applicable to
     dynamic rule only.
    :type blade_name: str
    :param forward_link: Forward link to an external document associated with
     the rule. Applicable to dynamic rule only.
    :type forward_link: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'recommendation_id': {'key': 'recommendationId', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'action_name': {'key': 'actionName', 'type': 'str'},
        'level': {'key': 'level', 'type': 'NotificationLevel'},
        'channels': {'key': 'channels', 'type': 'Channels'},
        'tags': {'key': 'tags', 'type': '[str]'},
        'is_dynamic': {'key': 'isDynamic', 'type': 'bool'},
        'extension_name': {'key': 'extensionName', 'type': 'str'},
        'blade_name': {'key': 'bladeName', 'type': 'str'},
        'forward_link': {'key': 'forwardLink', 'type': 'str'},
    }

    def __init__(self, name=None, display_name=None, message=None, recommendation_id=None, description=None, action_name=None, level=None, channels=None, tags=None, is_dynamic=None, extension_name=None, blade_name=None, forward_link=None):
        super(RecommendationRule, self).__init__()
        self.name = name
        self.display_name = display_name
        self.message = message
        self.recommendation_id = recommendation_id
        self.description = description
        self.action_name = action_name
        self.level = level
        self.channels = channels
        self.tags = tags
        self.is_dynamic = is_dynamic
        self.extension_name = extension_name
        self.blade_name = blade_name
        self.forward_link = forward_link
