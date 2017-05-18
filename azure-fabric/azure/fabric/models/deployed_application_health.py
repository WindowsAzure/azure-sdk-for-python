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


class DeployedApplicationHealth(Model):
    """The health of the deployed application.

    :param health_events:
    :type health_events: list of :class:`HealthEvent
     <azure.fabric.models.HealthEvent>`
    :param aggregated_health_state: Possible values include: 'Invalid', 'Ok',
     'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or :class:`enum
     <azure.fabric.models.enum>`
    :param unhealthy_evaluations:
    :type unhealthy_evaluations: str
    :param name:
    :type name: str
    :param node_name:
    :type node_name: str
    :param deployed_service_package_health_states:
    :type deployed_service_package_health_states:
     :class:`DeployedServicePackageHealthState
     <azure.fabric.models.DeployedServicePackageHealthState>`
    """

    _attribute_map = {
        'health_events': {'key': 'HealthEvents', 'type': '[HealthEvent]'},
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': 'str'},
        'name': {'key': 'Name', 'type': 'str'},
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'deployed_service_package_health_states': {'key': 'DeployedServicePackageHealthStates', 'type': 'DeployedServicePackageHealthState'},
    }

    def __init__(self, health_events=None, aggregated_health_state=None, unhealthy_evaluations=None, name=None, node_name=None, deployed_service_package_health_states=None):
        self.health_events = health_events
        self.aggregated_health_state = aggregated_health_state
        self.unhealthy_evaluations = unhealthy_evaluations
        self.name = name
        self.node_name = node_name
        self.deployed_service_package_health_states = deployed_service_package_health_states
