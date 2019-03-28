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


class MetricBaselinesResponse(Model):
    """The response to a metric baselines query.

    All required parameters must be populated in order to send to Azure.

    :param timespan: Required. The timespan for which the data was retrieved.
     Its value consists of two datetimes concatenated, separated by '/'.  This
     may be adjusted in the future and returned back from what was originally
     requested.
    :type timespan: str
    :param interval: Required. The interval (window size) for which the metric
     data was returned in.  This may be adjusted in the future and returned
     back from what was originally requested.  This is not present if a
     metadata request was made.
    :type interval: timedelta
    :param namespace: The namespace of the metrics been queried.
    :type namespace: str
    :param value: Required. the properties of the baseline.
    :type value: ~azure.mgmt.monitor.models.MetricBaseline
    """

    _validation = {
        'timespan': {'required': True},
        'interval': {'required': True},
        'value': {'required': True},
    }

    _attribute_map = {
        'timespan': {'key': 'timespan', 'type': 'str'},
        'interval': {'key': 'interval', 'type': 'duration'},
        'namespace': {'key': 'namespace', 'type': 'str'},
        'value': {'key': 'value', 'type': 'MetricBaseline'},
    }

    def __init__(self, *, timespan: str, interval, value, namespace: str=None, **kwargs) -> None:
        super(MetricBaselinesResponse, self).__init__(**kwargs)
        self.timespan = timespan
        self.interval = interval
        self.namespace = namespace
        self.value = value
