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


class ApplicationMetricDescription(Model):
    """Describes capacity information for a custom resource balancing metric. This
    can be used to limit the total consumption of this metric by the services
    of this application.
    .

    :param name: The name of the metric.
    :type name: str
    :param maximum_capacity: The maximum node capacity for Service Fabric
     application.
     This is the maximum Load for an instance of this application on a single
     node. Even if the capacity of node is greater than this value, Service
     Fabric will limit the total load of services within the application on
     each node to this value.
     If set to zero, capacity for this metric is unlimited on each node.
     When creating a new application with application capacity defined, the
     product of MaximumNodes and this value must always be smaller than or
     equal to TotalApplicationCapacity.
     When updating existing application with application capacity, the product
     of MaximumNodes and this value must always be smaller than or equal to
     TotalApplicationCapacity.
    :type maximum_capacity: long
    :param reservation_capacity: The node reservation capacity for Service
     Fabric application.
     This is the amount of load which is reserved on nodes which have instances
     of this application.
     If MinimumNodes is specified, then the product of these values will be the
     capacity reserved in the cluster for the application.
     If set to zero, no capacity is reserved for this metric.
     When setting application capacity or when updating application capacity;
     this value must be smaller than or equal to MaximumCapacity for each
     metric.
    :type reservation_capacity: long
    :param total_application_capacity: The total metric capacity for Service
     Fabric application.
     This is the total metric capacity for this application in the cluster.
     Service Fabric will try to limit the sum of loads of services within the
     application to this value.
     When creating a new application with application capacity defined, the
     product of MaximumNodes and MaximumCapacity must always be smaller than or
     equal to this value.
    :type total_application_capacity: long
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'maximum_capacity': {'key': 'maximumCapacity', 'type': 'long'},
        'reservation_capacity': {'key': 'reservationCapacity', 'type': 'long'},
        'total_application_capacity': {'key': 'totalApplicationCapacity', 'type': 'long'},
    }

    def __init__(self, *, name: str=None, maximum_capacity: int=None, reservation_capacity: int=None, total_application_capacity: int=None, **kwargs) -> None:
        super(ApplicationMetricDescription, self).__init__(**kwargs)
        self.name = name
        self.maximum_capacity = maximum_capacity
        self.reservation_capacity = reservation_capacity
        self.total_application_capacity = total_application_capacity
