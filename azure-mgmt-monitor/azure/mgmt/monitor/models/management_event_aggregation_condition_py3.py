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


class ManagementEventAggregationCondition(Model):
    """How the data that is collected should be combined over time.

    :param operator: the condition operator. Possible values include:
     'GreaterThan', 'GreaterThanOrEqual', 'LessThan', 'LessThanOrEqual'
    :type operator: str or ~azure.mgmt.monitor.models.ConditionOperator
    :param threshold: The threshold value that activates the alert.
    :type threshold: float
    :param window_size: the period of time (in ISO 8601 duration format) that
     is used to monitor alert activity based on the threshold. If specified
     then it must be between 5 minutes and 1 day.
    :type window_size: timedelta
    """

    _attribute_map = {
        'operator': {'key': 'operator', 'type': 'ConditionOperator'},
        'threshold': {'key': 'threshold', 'type': 'float'},
        'window_size': {'key': 'windowSize', 'type': 'duration'},
    }

    def __init__(self, *, operator=None, threshold: float=None, window_size=None, **kwargs) -> None:
        super(ManagementEventAggregationCondition, self).__init__(**kwargs)
        self.operator = operator
        self.threshold = threshold
        self.window_size = window_size
