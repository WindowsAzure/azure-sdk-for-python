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


class NetworkConfigurationDiagnosticResult(Model):
    """Network configuration diagnostic result corresponded to provided traffic
    query.

    :param traffic_query:
    :type traffic_query: ~azure.mgmt.network.v2018_06_01.models.TrafficQuery
    :param network_security_group_result:
    :type network_security_group_result:
     ~azure.mgmt.network.v2018_06_01.models.NetworkSecurityGroupResult
    """

    _attribute_map = {
        'traffic_query': {'key': 'trafficQuery', 'type': 'TrafficQuery'},
        'network_security_group_result': {'key': 'networkSecurityGroupResult', 'type': 'NetworkSecurityGroupResult'},
    }

    def __init__(self, *, traffic_query=None, network_security_group_result=None, **kwargs) -> None:
        super(NetworkConfigurationDiagnosticResult, self).__init__(**kwargs)
        self.traffic_query = traffic_query
        self.network_security_group_result = network_security_group_result
