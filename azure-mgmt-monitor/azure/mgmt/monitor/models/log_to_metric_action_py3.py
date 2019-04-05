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

from .action_py3 import Action


class LogToMetricAction(Action):
    """Specify action need to be taken when rule type is converting log to metric.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param criteria: Required. Severity of the alert
    :type criteria: ~azure.mgmt.monitor.models.Criteria
    """

    _validation = {
        'odatatype': {'required': True},
        'criteria': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': 'odata\\.type', 'type': 'str'},
        'criteria': {'key': 'criteria', 'type': 'Criteria'},
    }

    def __init__(self, *, criteria, **kwargs) -> None:
        super(LogToMetricAction, self).__init__(**kwargs)
        self.criteria = criteria
        self.odatatype = 'Microsoft.WindowsAzure.Management.Monitoring.Alerts.Models.Microsoft.AppInsights.Nexus.DataContracts.Resources.ScheduledQueryRules.LogToMetricAction'
