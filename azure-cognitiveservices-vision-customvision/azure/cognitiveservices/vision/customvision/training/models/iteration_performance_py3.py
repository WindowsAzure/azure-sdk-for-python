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


class IterationPerformance(Model):
    """Represents the detailed performance data for a trained iteration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar per_tag_performance: Gets the per-tag performance details for this
     iteration.
    :vartype per_tag_performance:
     list[~azure.cognitiveservices.vision.customvision.training.models.TagPerformance]
    :ivar precision: Gets the precision.
    :vartype precision: float
    :ivar precision_std_deviation: Gets the standard deviation for the
     precision.
    :vartype precision_std_deviation: float
    :ivar recall: Gets the recall.
    :vartype recall: float
    :ivar recall_std_deviation: Gets the standard deviation for the recall.
    :vartype recall_std_deviation: float
    :ivar average_precision: Gets the average precision when applicable.
    :vartype average_precision: float
    """

    _validation = {
        'per_tag_performance': {'readonly': True},
        'precision': {'readonly': True},
        'precision_std_deviation': {'readonly': True},
        'recall': {'readonly': True},
        'recall_std_deviation': {'readonly': True},
        'average_precision': {'readonly': True},
    }

    _attribute_map = {
        'per_tag_performance': {'key': 'perTagPerformance', 'type': '[TagPerformance]'},
        'precision': {'key': 'precision', 'type': 'float'},
        'precision_std_deviation': {'key': 'precisionStdDeviation', 'type': 'float'},
        'recall': {'key': 'recall', 'type': 'float'},
        'recall_std_deviation': {'key': 'recallStdDeviation', 'type': 'float'},
        'average_precision': {'key': 'averagePrecision', 'type': 'float'},
    }

    def __init__(self, **kwargs) -> None:
        super(IterationPerformance, self).__init__(**kwargs)
        self.per_tag_performance = None
        self.precision = None
        self.precision_std_deviation = None
        self.recall = None
        self.recall_std_deviation = None
        self.average_precision = None
