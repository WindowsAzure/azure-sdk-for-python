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


class Response(Model):
    """The response to a metrics query.

    All required parameters must be populated in order to send to Azure.

    :param cost: The integer value representing the cost of the query, for
     data case.
    :type cost: float
    :param timespan: Required. The timespan for which the data was retrieved.
     Its value consists of two datetimes concatenated, separated by '/'.  This
     may be adjusted in the future and returned back from what was originally
     requested.
    :type timespan: str
    :param interval: The interval (window size) for which the metric data was
     returned in.  This may be adjusted in the future and returned back from
     what was originally requested.  This is not present if a metadata request
     was made.
    :type interval: timedelta
    :param namespace: The namespace of the metrics been queried
    :type namespace: str
    :param resourceregion: The region of the resource been queried for
     metrics.
    :type resourceregion: str
    :param value: Required. the value of the collection.
    :type value: list[~azure.mgmt.monitor.models.Metric]
    """

    _validation = {
        'cost': {'minimum': 0},
        'timespan': {'required': True},
        'value': {'required': True},
    }

    _attribute_map = {
        'cost': {'key': 'cost', 'type': 'float'},
        'timespan': {'key': 'timespan', 'type': 'str'},
        'interval': {'key': 'interval', 'type': 'duration'},
        'namespace': {'key': 'namespace', 'type': 'str'},
        'resourceregion': {'key': 'resourceregion', 'type': 'str'},
        'value': {'key': 'value', 'type': '[Metric]'},
    }

    def __init__(self, *, timespan: str, value, cost: float=None, interval=None, namespace: str=None, resourceregion: str=None, **kwargs) -> None:
        super(Response, self).__init__(**kwargs)
        self.cost = cost
        self.timespan = timespan
        self.interval = interval
        self.namespace = namespace
        self.resourceregion = resourceregion
        self.value = value
