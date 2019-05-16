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

from .proxy_only_resource import ProxyOnlyResource


class DiagnosticDetectorResponse(ProxyOnlyResource):
    """Class representing Response from Diagnostic Detectors.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param start_time: Start time of the period
    :type start_time: datetime
    :param end_time: End time of the period
    :type end_time: datetime
    :param issue_detected: Flag representing Issue was detected.
    :type issue_detected: bool
    :param detector_definition: Detector's definition
    :type detector_definition: ~azure.mgmt.web.models.DetectorDefinition
    :param metrics: Metrics provided by the detector
    :type metrics: list[~azure.mgmt.web.models.DiagnosticMetricSet]
    :param abnormal_time_periods: List of Correlated events found by the
     detector
    :type abnormal_time_periods:
     list[~azure.mgmt.web.models.DetectorAbnormalTimePeriod]
    :param data: Additional Data that detector wants to send.
    :type data: list[list[~azure.mgmt.web.models.NameValuePair]]
    :param response_meta_data: Meta Data
    :type response_meta_data: ~azure.mgmt.web.models.ResponseMetaData
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'issue_detected': {'key': 'properties.issueDetected', 'type': 'bool'},
        'detector_definition': {'key': 'properties.detectorDefinition', 'type': 'DetectorDefinition'},
        'metrics': {'key': 'properties.metrics', 'type': '[DiagnosticMetricSet]'},
        'abnormal_time_periods': {'key': 'properties.abnormalTimePeriods', 'type': '[DetectorAbnormalTimePeriod]'},
        'data': {'key': 'properties.data', 'type': '[[NameValuePair]]'},
        'response_meta_data': {'key': 'properties.responseMetaData', 'type': 'ResponseMetaData'},
    }

    def __init__(self, **kwargs):
        super(DiagnosticDetectorResponse, self).__init__(**kwargs)
        self.start_time = kwargs.get('start_time', None)
        self.end_time = kwargs.get('end_time', None)
        self.issue_detected = kwargs.get('issue_detected', None)
        self.detector_definition = kwargs.get('detector_definition', None)
        self.metrics = kwargs.get('metrics', None)
        self.abnormal_time_periods = kwargs.get('abnormal_time_periods', None)
        self.data = kwargs.get('data', None)
        self.response_meta_data = kwargs.get('response_meta_data', None)
