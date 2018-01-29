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


class DeployedApplicationHealth(EntityHealth):
    """Information about the health of an application deployed on a Service Fabric
    node.

    :param aggregated_health_state: Possible values include: 'Invalid', 'Ok',
     'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or ~azure.servicefabric.models.enum
    :param health_events: The list of health events reported on the entity.
    :type health_events: list[~azure.servicefabric.models.HealthEvent]
    :param unhealthy_evaluations:
    :type unhealthy_evaluations:
     list[~azure.servicefabric.models.HealthEvaluationWrapper]
    :param health_statistics:
    :type health_statistics: ~azure.servicefabric.models.HealthStatistics
    :param name:
    :type name: str
    :param node_name:
    :type node_name: str
    :param deployed_service_package_health_states:
    :type deployed_service_package_health_states:
     list[~azure.servicefabric.models.DeployedServicePackageHealthState]
    """

    _attribute_map = {
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'health_events': {'key': 'HealthEvents', 'type': '[HealthEvent]'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[HealthEvaluationWrapper]'},
        'health_statistics': {'key': 'HealthStatistics', 'type': 'HealthStatistics'},
        'name': {'key': 'Name', 'type': 'str'},
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'deployed_service_package_health_states': {'key': 'DeployedServicePackageHealthStates', 'type': '[DeployedServicePackageHealthState]'},
    }

    def __init__(self, aggregated_health_state=None, health_events=None, unhealthy_evaluations=None, health_statistics=None, name=None, node_name=None, deployed_service_package_health_states=None):
        super(DeployedApplicationHealth, self).__init__(aggregated_health_state=aggregated_health_state, health_events=health_events, unhealthy_evaluations=unhealthy_evaluations, health_statistics=health_statistics)
        self.name = name
        self.node_name = node_name
        self.deployed_service_package_health_states = deployed_service_package_health_states
