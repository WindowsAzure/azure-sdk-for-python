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


class Endpoint(Model):
    """Class representing a Traffic Manager endpoint.

    :param id: Gets or sets the ID of the Traffic Manager endpoint.
    :type id: str
    :param name: Gets or sets the name of the Traffic Manager endpoint.
    :type name: str
    :param type: Gets or sets the endpoint type of the Traffic Manager
     endpoint.
    :type type: str
    :param target_resource_id: Gets or sets the Azure Resource URI of the of
     the endpoint.  Not applicable to endpoints of type 'ExternalEndpoints'.
    :type target_resource_id: str
    :param target: Gets or sets the fully-qualified DNS name of the endpoint.
     Traffic Manager returns this value in DNS responses to direct traffic to
     this endpoint.
    :type target: str
    :param endpoint_status: Gets or sets the status of the endpoint..  If the
     endpoint is Enabled, it is probed for endpoint health and is included in
     the traffic routing method.  Possible values are 'Enabled' and 'Disabled'.
    :type endpoint_status: str
    :param weight: Gets or sets the weight of this endpoint when using the
     'Weighted' traffic routing method. Possible values are from 1 to 1000.
    :type weight: long
    :param priority: Gets or sets the priority of this endpoint when using the
     ‘Priority’ traffic routing method. Possible values are from 1 to 1000,
     lower values represent higher priority. This is an optional parameter.  If
     specified, it must be specified on all endpoints, and no two endpoints can
     share the same priority value.
    :type priority: long
    :param endpoint_location: Specifies the location of the external or nested
     endpoints when using the ‘Performance’ traffic routing method.
    :type endpoint_location: str
    :param endpoint_monitor_status: Gets or sets the monitoring status of the
     endpoint.
    :type endpoint_monitor_status: str
    :param min_child_endpoints: Gets or sets the minimum number of endpoints
     that must be available in the child profile in order for the parent
     profile to be considered available. Only applicable to endpoint of type
     'NestedEndpoints'.
    :type min_child_endpoints: long
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'target_resource_id': {'key': 'properties.targetResourceId', 'type': 'str'},
        'target': {'key': 'properties.target', 'type': 'str'},
        'endpoint_status': {'key': 'properties.endpointStatus', 'type': 'str'},
        'weight': {'key': 'properties.weight', 'type': 'long'},
        'priority': {'key': 'properties.priority', 'type': 'long'},
        'endpoint_location': {'key': 'properties.endpointLocation', 'type': 'str'},
        'endpoint_monitor_status': {'key': 'properties.endpointMonitorStatus', 'type': 'str'},
        'min_child_endpoints': {'key': 'properties.minChildEndpoints', 'type': 'long'},
    }

    def __init__(self, id=None, name=None, type=None, target_resource_id=None, target=None, endpoint_status=None, weight=None, priority=None, endpoint_location=None, endpoint_monitor_status=None, min_child_endpoints=None):
        self.id = id
        self.name = name
        self.type = type
        self.target_resource_id = target_resource_id
        self.target = target
        self.endpoint_status = endpoint_status
        self.weight = weight
        self.priority = priority
        self.endpoint_location = endpoint_location
        self.endpoint_monitor_status = endpoint_monitor_status
        self.min_child_endpoints = min_child_endpoints
