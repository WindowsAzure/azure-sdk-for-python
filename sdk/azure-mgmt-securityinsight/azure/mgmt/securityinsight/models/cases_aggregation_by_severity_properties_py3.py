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


class CasesAggregationBySeverityProperties(Model):
    """Aggregative results of cases by severity property bag.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar total_critical_severity: Total amount of open cases with severity
     Critical
    :vartype total_critical_severity: int
    :ivar total_high_severity: Total amount of open cases with severity High
    :vartype total_high_severity: int
    :ivar total_informational_severity: Total amount of open cases with
     severity Informational
    :vartype total_informational_severity: int
    :ivar total_low_severity: Total amount of open cases with severity Low
    :vartype total_low_severity: int
    :ivar total_medium_severity: Total amount of open cases with severity
     medium
    :vartype total_medium_severity: int
    """

    _validation = {
        'total_critical_severity': {'readonly': True},
        'total_high_severity': {'readonly': True},
        'total_informational_severity': {'readonly': True},
        'total_low_severity': {'readonly': True},
        'total_medium_severity': {'readonly': True},
    }

    _attribute_map = {
        'total_critical_severity': {'key': 'totalCriticalSeverity', 'type': 'int'},
        'total_high_severity': {'key': 'totalHighSeverity', 'type': 'int'},
        'total_informational_severity': {'key': 'totalInformationalSeverity', 'type': 'int'},
        'total_low_severity': {'key': 'totalLowSeverity', 'type': 'int'},
        'total_medium_severity': {'key': 'totalMediumSeverity', 'type': 'int'},
    }

    def __init__(self, **kwargs) -> None:
        super(CasesAggregationBySeverityProperties, self).__init__(**kwargs)
        self.total_critical_severity = None
        self.total_high_severity = None
        self.total_informational_severity = None
        self.total_low_severity = None
        self.total_medium_severity = None
