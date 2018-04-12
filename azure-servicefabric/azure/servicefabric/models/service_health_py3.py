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

from .entity_health import EntityHealth


class ServiceHealth(EntityHealth):
    """Information about the health of a Service Fabric service.

    :param aggregated_health_state: The HealthState representing the
     aggregated health state of the entity computed by Health Manager.
     The health evaluation of the entity reflects all events reported on the
     entity and its children (if any).
     The aggregation is done by applying the desired health policy.
     . Possible values include: 'Invalid', 'Ok', 'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or
     ~azure.servicefabric.models.HealthState
    :param health_events: The list of health events reported on the entity.
    :type health_events: list[~azure.servicefabric.models.HealthEvent]
    :param unhealthy_evaluations: The unhealthy evaluations that show why the
     current aggregated health state was returned by Health Manager.
    :type unhealthy_evaluations:
     list[~azure.servicefabric.models.HealthEvaluationWrapper]
    :param health_statistics: Shows the health statistics for all children
     types of the queried entity.
    :type health_statistics: ~azure.servicefabric.models.HealthStatistics
    :param name: The name of the service whose health information is described
     by this object.
    :type name: str
    :param partition_health_states: The list of partition health states
     associated with the service.
    :type partition_health_states:
     list[~azure.servicefabric.models.PartitionHealthState]
    """

    _attribute_map = {
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'health_events': {'key': 'HealthEvents', 'type': '[HealthEvent]'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[HealthEvaluationWrapper]'},
        'health_statistics': {'key': 'HealthStatistics', 'type': 'HealthStatistics'},
        'name': {'key': 'Name', 'type': 'str'},
        'partition_health_states': {'key': 'PartitionHealthStates', 'type': '[PartitionHealthState]'},
    }

    def __init__(self, *, aggregated_health_state=None, health_events=None, unhealthy_evaluations=None, health_statistics=None, name: str=None, partition_health_states=None, **kwargs) -> None:
        super(ServiceHealth, self).__init__(aggregated_health_state=aggregated_health_state, health_events=health_events, unhealthy_evaluations=unhealthy_evaluations, health_statistics=health_statistics, **kwargs)
        self.name = name
        self.partition_health_states = partition_health_states
