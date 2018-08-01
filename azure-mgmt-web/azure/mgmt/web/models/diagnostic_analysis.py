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


class DiagnosticAnalysis(ProxyOnlyResource):
    """Class representing a diagnostic analysis done on an application.

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
    :param abnormal_time_periods: List of time periods.
    :type abnormal_time_periods:
     list[~azure.mgmt.web.models.AbnormalTimePeriod]
    :param payload: Data by each detector
    :type payload: list[~azure.mgmt.web.models.AnalysisData]
    :param non_correlated_detectors: Data by each detector for detectors that
     did not corelate
    :type non_correlated_detectors:
     list[~azure.mgmt.web.models.DetectorDefinition]
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
        'abnormal_time_periods': {'key': 'properties.abnormalTimePeriods', 'type': '[AbnormalTimePeriod]'},
        'payload': {'key': 'properties.payload', 'type': '[AnalysisData]'},
        'non_correlated_detectors': {'key': 'properties.nonCorrelatedDetectors', 'type': '[DetectorDefinition]'},
    }

    def __init__(self, **kwargs):
        super(DiagnosticAnalysis, self).__init__(**kwargs)
        self.start_time = kwargs.get('start_time', None)
        self.end_time = kwargs.get('end_time', None)
        self.abnormal_time_periods = kwargs.get('abnormal_time_periods', None)
        self.payload = kwargs.get('payload', None)
        self.non_correlated_detectors = kwargs.get('non_correlated_detectors', None)
