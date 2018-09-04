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


class ServiceHealthStateFilter(Model):
    """Defines matching criteria to determine whether a service should be included
    as a child of an application in the cluster health chunk.
    The services are only returned if the parent application matches a filter
    specified in the cluster health chunk query description.
    One filter can match zero, one or multiple services, depending on its
    properties.

    :param service_name_filter: The name of the service that matches the
     filter. The filter is applied only to the specified service, if it exists.
     If the service doesn't exist, no service is returned in the cluster health
     chunk based on this filter.
     If the service exists, it is included as the application's child if the
     health state matches the other filter properties.
     If not specified, all services that match the parent filters (if any) are
     taken into consideration and matched against the other filter members,
     like health state filter.
    :type service_name_filter: str
    :param health_state_filter: The filter for the health state of the
     services. It allows selecting services if they match the desired health
     states.
     The possible values are integer value of one of the following health
     states. Only services that match the filter are returned. All services are
     used to evaluate the cluster aggregated health state.
     If not specified, default value is None, unless the service name is
     specified. If the filter has default value and service name is specified,
     the matching service is returned.
     The state values are flag-based enumeration, so the value could be a
     combination of these values obtained using bitwise 'OR' operator.
     For example, if the provided value is 6, it matches services with
     HealthState value of OK (2) and Warning (4).
     - Default - Default value. Matches any HealthState. The value is zero.
     - None - Filter that doesn't match any HealthState value. Used in order to
     return no results on a given collection of states. The value is 1.
     - Ok - Filter that matches input with HealthState value Ok. The value is
     2.
     - Warning - Filter that matches input with HealthState value Warning. The
     value is 4.
     - Error - Filter that matches input with HealthState value Error. The
     value is 8.
     - All - Filter that matches input with any HealthState value. The value is
     65535. Default value: 0 .
    :type health_state_filter: int
    :param partition_filters: Defines a list of filters that specify which
     partitions to be included in the returned cluster health chunk as children
     of the service. The partitions are returned only if the parent service
     matches a filter.
     If the list is empty, no partitions are returned. All the partitions are
     used to evaluate the parent service aggregated health state, regardless of
     the input filters.
     The service filter may specify multiple partition filters.
     For example, it can specify a filter to return all partitions with health
     state Error and another filter to always include a partition identified by
     its partition ID.
    :type partition_filters:
     list[~azure.servicefabric.models.PartitionHealthStateFilter]
    """

    _attribute_map = {
        'service_name_filter': {'key': 'ServiceNameFilter', 'type': 'str'},
        'health_state_filter': {'key': 'HealthStateFilter', 'type': 'int'},
        'partition_filters': {'key': 'PartitionFilters', 'type': '[PartitionHealthStateFilter]'},
    }

    def __init__(self, **kwargs):
        super(ServiceHealthStateFilter, self).__init__(**kwargs)
        self.service_name_filter = kwargs.get('service_name_filter', None)
        self.health_state_filter = kwargs.get('health_state_filter', 0)
        self.partition_filters = kwargs.get('partition_filters', None)
