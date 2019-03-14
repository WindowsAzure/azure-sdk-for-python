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

from .metric_alert_criteria_py3 import MetricAlertCriteria


class MetricAlertMultipleResourceMultipleMetricCriteria(MetricAlertCriteria):
    """Specifies the metric alert criteria for multiple resource that has multiple
    metric criteria.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param all_of: the list of multiple metric criteria for this 'all of'
     operation.
    :type all_of: list[~azure.mgmt.monitor.models.MultiMetricCriteria]
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'odatatype': {'key': 'odata\\.type', 'type': 'str'},
        'all_of': {'key': 'allOf', 'type': '[MultiMetricCriteria]'},
    }

    def __init__(self, *, additional_properties=None, all_of=None, **kwargs) -> None:
        super(MetricAlertMultipleResourceMultipleMetricCriteria, self).__init__(additional_properties=additional_properties, **kwargs)
        self.all_of = all_of
        self.odatatype = 'Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria'
