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


class SloUsageMetric(Model):
    """Represents a Slo Usage Metric.

    :param service_level_objective: The serviceLevelObjective for SLO usage
     metric. Possible values include: 'Basic', 'S0', 'S1', 'S2', 'S3', 'P1',
     'P2', 'P3'
    :type service_level_objective: str or :class:`ServiceObjectiveName
     <azure.mgmt.sql.models.ServiceObjectiveName>`
    :param service_level_objective_id: The serviceLevelObjectiveId for SLO
     usage metric.
    :type service_level_objective_id: str
    :param in_range_time_ratio: Gets or sets inRangeTimeRatio for SLO usage
     metric.
    :type in_range_time_ratio: float
    """

    _attribute_map = {
        'service_level_objective': {'key': 'serviceLevelObjective', 'type': 'str'},
        'service_level_objective_id': {'key': 'serviceLevelObjectiveId', 'type': 'str'},
        'in_range_time_ratio': {'key': 'inRangeTimeRatio', 'type': 'float'},
    }

    def __init__(self, service_level_objective=None, service_level_objective_id=None, in_range_time_ratio=None):
        self.service_level_objective = service_level_objective
        self.service_level_objective_id = service_level_objective_id
        self.in_range_time_ratio = in_range_time_ratio
