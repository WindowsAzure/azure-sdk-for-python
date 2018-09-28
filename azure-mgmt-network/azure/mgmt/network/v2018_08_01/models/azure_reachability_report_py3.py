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


class AzureReachabilityReport(Model):
    """Azure reachability report details.

    All required parameters must be populated in order to send to Azure.

    :param aggregation_level: Required. The aggregation level of Azure
     reachability report. Can be Country, State or City.
    :type aggregation_level: str
    :param provider_location: Required.
    :type provider_location:
     ~azure.mgmt.network.v2018_08_01.models.AzureReachabilityReportLocation
    :param reachability_report: Required. List of Azure reachability report
     items.
    :type reachability_report:
     list[~azure.mgmt.network.v2018_08_01.models.AzureReachabilityReportItem]
    """

    _validation = {
        'aggregation_level': {'required': True},
        'provider_location': {'required': True},
        'reachability_report': {'required': True},
    }

    _attribute_map = {
        'aggregation_level': {'key': 'aggregationLevel', 'type': 'str'},
        'provider_location': {'key': 'providerLocation', 'type': 'AzureReachabilityReportLocation'},
        'reachability_report': {'key': 'reachabilityReport', 'type': '[AzureReachabilityReportItem]'},
    }

    def __init__(self, *, aggregation_level: str, provider_location, reachability_report, **kwargs) -> None:
        super(AzureReachabilityReport, self).__init__(**kwargs)
        self.aggregation_level = aggregation_level
        self.provider_location = provider_location
        self.reachability_report = reachability_report
