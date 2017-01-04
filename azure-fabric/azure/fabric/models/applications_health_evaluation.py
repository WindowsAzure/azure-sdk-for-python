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

from .health_evaluation import HealthEvaluation


class ApplicationsHealthEvaluation(HealthEvaluation):
    """The evaluation of the applications health.

    :param description:
    :type description: str
    :param aggregated_health_state: Possible values include: 'Invalid', 'Ok',
     'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or :class:`enum
     <azure.fabric.models.enum>`
    :param kind: Polymorphic Discriminator
    :type kind: str
    :param unhealthy_evaluations:
    :type unhealthy_evaluations: list of :class:`UnhealthyEvaluation
     <azure.fabric.models.UnhealthyEvaluation>`
    :param total_count:
    :type total_count: int
    :param max_percent_unhealthy_applications:
    :type max_percent_unhealthy_applications: int
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'description': {'key': 'Description', 'type': 'str'},
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[UnhealthyEvaluation]'},
        'total_count': {'key': 'TotalCount', 'type': 'int'},
        'max_percent_unhealthy_applications': {'key': 'MaxPercentUnhealthyApplications', 'type': 'int'},
    }

    def __init__(self, description=None, aggregated_health_state=None, unhealthy_evaluations=None, total_count=None, max_percent_unhealthy_applications=None):
        super(ApplicationsHealthEvaluation, self).__init__(description=description, aggregated_health_state=aggregated_health_state)
        self.unhealthy_evaluations = unhealthy_evaluations
        self.total_count = total_count
        self.max_percent_unhealthy_applications = max_percent_unhealthy_applications
        self.kind = 'Applications'
