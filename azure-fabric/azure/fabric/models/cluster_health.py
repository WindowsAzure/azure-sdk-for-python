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


class ClusterHealth(Model):
    """The health of the cluster.

    :param health_events:
    :type health_events: list of :class:`HealthEvent
     <azure.fabric.models.HealthEvent>`
    :param aggregated_health_state: Possible values include: 'Invalid', 'Ok',
     'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or :class:`enum
     <azure.fabric.models.enum>`
    :param unhealthy_evaluations:
    :type unhealthy_evaluations: list of :class:`UnhealthyEvaluation
     <azure.fabric.models.UnhealthyEvaluation>`
    :param node_health_states:
    :type node_health_states: list of
     :class:`ClusterHealthNodeHealthStatesItem
     <azure.fabric.models.ClusterHealthNodeHealthStatesItem>`
    :param application_health_state:
    :type application_health_state: list of
     :class:`ClusterHealthApplicationHealthStateItem
     <azure.fabric.models.ClusterHealthApplicationHealthStateItem>`
    """

    _attribute_map = {
        'health_events': {'key': 'HealthEvents', 'type': '[HealthEvent]'},
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[UnhealthyEvaluation]'},
        'node_health_states': {'key': 'NodeHealthStates', 'type': '[ClusterHealthNodeHealthStatesItem]'},
        'application_health_state': {'key': 'ApplicationHealthState', 'type': '[ClusterHealthApplicationHealthStateItem]'},
    }

    def __init__(self, health_events=None, aggregated_health_state=None, unhealthy_evaluations=None, node_health_states=None, application_health_state=None):
        self.health_events = health_events
        self.aggregated_health_state = aggregated_health_state
        self.unhealthy_evaluations = unhealthy_evaluations
        self.node_health_states = node_health_states
        self.application_health_state = application_health_state
