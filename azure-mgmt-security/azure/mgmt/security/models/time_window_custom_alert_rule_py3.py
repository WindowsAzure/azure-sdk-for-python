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


class TimeWindowCustomAlertRule(Model):
    """A custom alert rule that checks if the number of activities (depends on the
    custom alert type) in a time window is within the given range.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar display_name: The display name of the custom alert.
    :vartype display_name: str
    :ivar description: The description of the custom alert.
    :vartype description: str
    :param is_enabled: Required. Whether the custom alert is enabled.
    :type is_enabled: bool
    :param rule_type: Required. The type of the custom alert rule.
    :type rule_type: str
    :param min_threshold: Required. The minimum threshold.
    :type min_threshold: int
    :param max_threshold: Required. The maximum threshold.
    :type max_threshold: int
    :param time_window_size: Required. The time window size in iso8601 format.
    :type time_window_size: timedelta
    """

    _validation = {
        'display_name': {'readonly': True},
        'description': {'readonly': True},
        'is_enabled': {'required': True},
        'rule_type': {'required': True},
        'min_threshold': {'required': True},
        'max_threshold': {'required': True},
        'time_window_size': {'required': True},
    }

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'is_enabled': {'key': 'isEnabled', 'type': 'bool'},
        'rule_type': {'key': 'ruleType', 'type': 'str'},
        'min_threshold': {'key': 'minThreshold', 'type': 'int'},
        'max_threshold': {'key': 'maxThreshold', 'type': 'int'},
        'time_window_size': {'key': 'timeWindowSize', 'type': 'duration'},
    }

    def __init__(self, *, is_enabled: bool, rule_type: str, min_threshold: int, max_threshold: int, time_window_size, **kwargs) -> None:
        super(TimeWindowCustomAlertRule, self).__init__(**kwargs)
        self.display_name = None
        self.description = None
        self.is_enabled = is_enabled
        self.rule_type = rule_type
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.time_window_size = time_window_size
