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

from .custom_rule_py3 import CustomRule


class RateLimitRule(CustomRule):
    """Defines a rate limiting rule that can be included in a waf policy.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Defines the name of the custom rule
    :type name: str
    :param enabled_state: Describes if the custom rule is in enabled or
     disabled state. Defaults to Enabled if not specified. Possible values
     include: 'Disabled', 'Enabled'
    :type enabled_state: str or ~azure.mgmt.cdn.models.CustomRuleEnabledState
    :param priority: Required. Defines in what order this rule be evaluated in
     the overall list of custom rules
    :type priority: int
    :param match_conditions: Required. List of match conditions.
    :type match_conditions: list[~azure.mgmt.cdn.models.MatchCondition]
    :param action: Required. Describes what action to be applied when rule
     matches
    :type action: ~azure.mgmt.cdn.models.ActionType
    :param rate_limit_threshold: Required. Defines rate limit threshold.
    :type rate_limit_threshold: int
    :param rate_limit_duration_in_minutes: Required. Defines rate limit
     duration. Default is 1 minute.
    :type rate_limit_duration_in_minutes: int
    """

    _validation = {
        'name': {'required': True},
        'priority': {'required': True},
        'match_conditions': {'required': True},
        'action': {'required': True},
        'rate_limit_threshold': {'required': True, 'minimum': 0},
        'rate_limit_duration_in_minutes': {'required': True, 'maximum': 60, 'minimum': 0},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'enabled_state': {'key': 'enabledState', 'type': 'str'},
        'priority': {'key': 'priority', 'type': 'int'},
        'match_conditions': {'key': 'matchConditions', 'type': '[MatchCondition]'},
        'action': {'key': 'action', 'type': 'ActionType'},
        'rate_limit_threshold': {'key': 'rateLimitThreshold', 'type': 'int'},
        'rate_limit_duration_in_minutes': {'key': 'rateLimitDurationInMinutes', 'type': 'int'},
    }

    def __init__(self, *, name: str, priority: int, match_conditions, action, rate_limit_threshold: int, rate_limit_duration_in_minutes: int, enabled_state=None, **kwargs) -> None:
        super(RateLimitRule, self).__init__(name=name, enabled_state=enabled_state, priority=priority, match_conditions=match_conditions, action=action, **kwargs)
        self.rate_limit_threshold = rate_limit_threshold
        self.rate_limit_duration_in_minutes = rate_limit_duration_in_minutes
