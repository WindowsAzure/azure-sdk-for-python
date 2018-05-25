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

from .proxy_resource_py3 import ProxyResource


class HeatMapModel(ProxyResource):
    """Class representing a Traffic Manager HeatMap.

    :param id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficManagerProfiles/{resourceName}
    :type id: str
    :param name: The name of the resource
    :type name: str
    :param type: The type of the resource. Ex-
     Microsoft.Network/trafficmanagerProfiles.
    :type type: str
    :param start_time: The beginning of the time window for this HeatMap,
     inclusive.
    :type start_time: datetime
    :param end_time: The ending of the time window for this HeatMap,
     exclusive.
    :type end_time: datetime
    :param endpoints: The endpoints used in this HeatMap calculation.
    :type endpoints: list[~azure.mgmt.trafficmanager.models.HeatMapEndpoint]
    :param traffic_flows: The traffic flows produced in this HeatMap
     calculation.
    :type traffic_flows: list[~azure.mgmt.trafficmanager.models.TrafficFlow]
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'endpoints': {'key': 'properties.endpoints', 'type': '[HeatMapEndpoint]'},
        'traffic_flows': {'key': 'properties.trafficFlows', 'type': '[TrafficFlow]'},
    }

    def __init__(self, *, id: str=None, name: str=None, type: str=None, start_time=None, end_time=None, endpoints=None, traffic_flows=None, **kwargs) -> None:
        super(HeatMapModel, self).__init__(id=id, name=name, type=type, **kwargs)
        self.start_time = start_time
        self.end_time = end_time
        self.endpoints = endpoints
        self.traffic_flows = traffic_flows
