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


class MetricValue(Model):
    """Represents metrics values.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar _count: The number of values for the metric.
    :vartype _count: float
    :ivar average: The average value of the metric.
    :vartype average: float
    :ivar maximum: The max value of the metric.
    :vartype maximum: float
    :ivar minimum: The min value of the metric.
    :vartype minimum: float
    :ivar timestamp: The metric timestamp (ISO-8601 format).
    :vartype timestamp: datetime
    :ivar total: The total value of the metric.
    :vartype total: float
    """

    _validation = {
        '_count': {'readonly': True},
        'average': {'readonly': True},
        'maximum': {'readonly': True},
        'minimum': {'readonly': True},
        'timestamp': {'readonly': True},
        'total': {'readonly': True},
    }

    _attribute_map = {
        '_count': {'key': '_count', 'type': 'float'},
        'average': {'key': 'average', 'type': 'float'},
        'maximum': {'key': 'maximum', 'type': 'float'},
        'minimum': {'key': 'minimum', 'type': 'float'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'total': {'key': 'total', 'type': 'float'},
    }

    def __init__(self, **kwargs) -> None:
        super(MetricValue, self).__init__(**kwargs)
        self._count = None
        self.average = None
        self.maximum = None
        self.minimum = None
        self.timestamp = None
        self.total = None
