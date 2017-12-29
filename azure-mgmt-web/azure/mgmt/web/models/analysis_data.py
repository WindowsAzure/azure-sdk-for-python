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


class AnalysisData(Model):
    """Class Representing Detector Evidence used for analysis.

    :param source: Name of the Detector
    :type source: str
    :param detector_definition: Detector Definition
    :type detector_definition: ~azure.mgmt.web.models.DetectorDefinition
    :param metrics: Source Metrics
    :type metrics: list[~azure.mgmt.web.models.DiagnosticMetricSet]
    :param data: Additional Source Data
    :type data: list[list[~azure.mgmt.web.models.NameValuePair]]
    :param detector_meta_data: Detector Meta Data
    :type detector_meta_data: ~azure.mgmt.web.models.ResponseMetaData
    """

    _attribute_map = {
        'source': {'key': 'source', 'type': 'str'},
        'detector_definition': {'key': 'detectorDefinition', 'type': 'DetectorDefinition'},
        'metrics': {'key': 'metrics', 'type': '[DiagnosticMetricSet]'},
        'data': {'key': 'data', 'type': '[[NameValuePair]]'},
        'detector_meta_data': {'key': 'detectorMetaData', 'type': 'ResponseMetaData'},
    }

    def __init__(self, source=None, detector_definition=None, metrics=None, data=None, detector_meta_data=None):
        super(AnalysisData, self).__init__()
        self.source = source
        self.detector_definition = detector_definition
        self.metrics = metrics
        self.data = data
        self.detector_meta_data = detector_meta_data
