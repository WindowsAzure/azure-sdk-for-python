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

from .alerts_summary_by_severity_and_monitor_condition_py3 import AlertsSummaryBySeverityAndMonitorCondition


class AlertsSummaryPropertiesSummaryBySeverityAndMonitorCondition(AlertsSummaryBySeverityAndMonitorCondition):
    """Summary of alerts by severity and monitor condition.

    :param sev0: Summary of alerts by monitor condition with severity 'Sev0'
    :type sev0:
     ~azure.mgmt.alertsmanagement.models.AlertsSummaryBySeverityAndMonitorConditionSev0
    :param sev1: Summary of alerts by monitor condition with severity 'Sev1'
    :type sev1:
     ~azure.mgmt.alertsmanagement.models.AlertsSummaryBySeverityAndMonitorConditionSev1
    :param sev2: Summary of alerts by monitor condition with severity 'Sev2'
    :type sev2:
     ~azure.mgmt.alertsmanagement.models.AlertsSummaryBySeverityAndMonitorConditionSev2
    :param sev3: Summary of alerts by monitor condition with severity 'Sev3'
    :type sev3:
     ~azure.mgmt.alertsmanagement.models.AlertsSummaryBySeverityAndMonitorConditionSev3
    :param sev4: Summary of alerts by monitor condition with severity 'Sev4'
    :type sev4:
     ~azure.mgmt.alertsmanagement.models.AlertsSummaryBySeverityAndMonitorConditionSev4
    """

    _attribute_map = {
        'sev0': {'key': 'sev0', 'type': 'AlertsSummaryBySeverityAndMonitorConditionSev0'},
        'sev1': {'key': 'sev1', 'type': 'AlertsSummaryBySeverityAndMonitorConditionSev1'},
        'sev2': {'key': 'sev2', 'type': 'AlertsSummaryBySeverityAndMonitorConditionSev2'},
        'sev3': {'key': 'sev3', 'type': 'AlertsSummaryBySeverityAndMonitorConditionSev3'},
        'sev4': {'key': 'sev4', 'type': 'AlertsSummaryBySeverityAndMonitorConditionSev4'},
    }

    def __init__(self, *, sev0=None, sev1=None, sev2=None, sev3=None, sev4=None, **kwargs) -> None:
        super(AlertsSummaryPropertiesSummaryBySeverityAndMonitorCondition, self).__init__(sev0=sev0, sev1=sev1, sev2=sev2, sev3=sev3, sev4=sev4, **kwargs)
