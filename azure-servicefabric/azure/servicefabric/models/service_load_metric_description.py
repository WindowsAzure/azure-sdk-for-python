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


class ServiceLoadMetricDescription(Model):
    """Specifies a metric to load balance a service during runtime.

    :param name: The name of the metric. If the service chooses to report load
     during runtime, the load metric name should match the name that is
     specified in Name exactly. Note that metric names are case sensitive.
    :type name: str
    :param weight: Possible values include: 'Zero', 'Low', 'Medium', 'High'
    :type weight: str or ~azure.servicefabric.models.enum
    :param primary_default_load: Used only for Stateful services. The default
     amount of load, as a number, that this service creates for this metric
     when it is a Primary replica.
    :type primary_default_load: int
    :param secondary_default_load: Used only for Stateful services. The
     default amount of load, as a number, that this service creates for this
     metric when it is a Secondary replica.
    :type secondary_default_load: int
    :param default_load: Used only for Stateless services. The default amount
     of load, as a number, that this service creates for this metric.
    :type default_load: int
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str'},
        'weight': {'key': 'Weight', 'type': 'str'},
        'primary_default_load': {'key': 'PrimaryDefaultLoad', 'type': 'int'},
        'secondary_default_load': {'key': 'SecondaryDefaultLoad', 'type': 'int'},
        'default_load': {'key': 'DefaultLoad', 'type': 'int'},
    }

    def __init__(self, name, weight=None, primary_default_load=None, secondary_default_load=None, default_load=None):
        super(ServiceLoadMetricDescription, self).__init__()
        self.name = name
        self.weight = weight
        self.primary_default_load = primary_default_load
        self.secondary_default_load = secondary_default_load
        self.default_load = default_load
