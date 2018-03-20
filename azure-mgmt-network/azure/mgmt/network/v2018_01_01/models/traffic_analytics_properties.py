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


class TrafficAnalyticsProperties(Model):
    """Parameters that define the configuration of traffic analytics.

    All required parameters must be populated in order to send to Azure.

    :param network_watcher_flow_analytics_configuration: Required.
    :type network_watcher_flow_analytics_configuration:
     ~azure.mgmt.network.v2018_01_01.models.TrafficAnalyticsConfigurationProperties
    """

    _validation = {
        'network_watcher_flow_analytics_configuration': {'required': True},
    }

    _attribute_map = {
        'network_watcher_flow_analytics_configuration': {'key': 'networkWatcherFlowAnalyticsConfiguration', 'type': 'TrafficAnalyticsConfigurationProperties'},
    }

    def __init__(self, **kwargs):
        super(TrafficAnalyticsProperties, self).__init__(**kwargs)
        self.network_watcher_flow_analytics_configuration = kwargs.get('network_watcher_flow_analytics_configuration', None)
