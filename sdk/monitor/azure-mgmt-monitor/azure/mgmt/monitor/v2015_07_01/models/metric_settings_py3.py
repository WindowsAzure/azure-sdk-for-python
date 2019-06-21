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


class MetricSettings(Model):
    """Part of MultiTenantDiagnosticSettings. Specifies the settings for a
    particular metric.

    All required parameters must be populated in order to send to Azure.

    :param time_grain: Required. the timegrain of the metric in ISO8601
     format.
    :type time_grain: timedelta
    :param enabled: Required. a value indicating whether this timegrain is
     enabled.
    :type enabled: bool
    :param retention_policy: the retention policy for this timegrain.
    :type retention_policy:
     ~azure.mgmt.monitor.v2015_07_01.models.RetentionPolicy
    """

    _validation = {
        'time_grain': {'required': True},
        'enabled': {'required': True},
    }

    _attribute_map = {
        'time_grain': {'key': 'timeGrain', 'type': 'duration'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'retention_policy': {'key': 'retentionPolicy', 'type': 'RetentionPolicy'},
    }

    def __init__(self, *, time_grain, enabled: bool, retention_policy=None, **kwargs) -> None:
        super(MetricSettings, self).__init__(**kwargs)
        self.time_grain = time_grain
        self.enabled = enabled
        self.retention_policy = retention_policy
