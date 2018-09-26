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

from .tracked_resource_py3 import TrackedResource


class Profile(TrackedResource):
    """Class representing a Traffic Manager profile.

    :param id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficManagerProfiles/{resourceName}
    :type id: str
    :param name: The name of the resource
    :type name: str
    :param type: The type of the resource. Ex-
     Microsoft.Network/trafficmanagerProfiles.
    :type type: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param location: The Azure Region where the resource lives
    :type location: str
    :param profile_status: The status of the Traffic Manager profile. Possible
     values include: 'Enabled', 'Disabled'
    :type profile_status: str or
     ~azure.mgmt.trafficmanager.models.ProfileStatus
    :param traffic_routing_method: The traffic routing method of the Traffic
     Manager profile. Possible values include: 'Performance', 'Priority',
     'Weighted', 'Geographic', 'MultiValue', 'Subnet'
    :type traffic_routing_method: str or
     ~azure.mgmt.trafficmanager.models.TrafficRoutingMethod
    :param dns_config: The DNS settings of the Traffic Manager profile.
    :type dns_config: ~azure.mgmt.trafficmanager.models.DnsConfig
    :param monitor_config: The endpoint monitoring settings of the Traffic
     Manager profile.
    :type monitor_config: ~azure.mgmt.trafficmanager.models.MonitorConfig
    :param endpoints: The list of endpoints in the Traffic Manager profile.
    :type endpoints: list[~azure.mgmt.trafficmanager.models.Endpoint]
    :param traffic_view_enrollment_status: Indicates whether Traffic View is
     'Enabled' or 'Disabled' for the Traffic Manager profile. Null, indicates
     'Disabled'. Enabling this feature will increase the cost of the Traffic
     Manage profile. Possible values include: 'Enabled', 'Disabled'
    :type traffic_view_enrollment_status: str or
     ~azure.mgmt.trafficmanager.models.TrafficViewEnrollmentStatus
    :param max_return: Maximum number of endpoints to be returned for
     MultiValue routing type.
    :type max_return: long
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'profile_status': {'key': 'properties.profileStatus', 'type': 'str'},
        'traffic_routing_method': {'key': 'properties.trafficRoutingMethod', 'type': 'str'},
        'dns_config': {'key': 'properties.dnsConfig', 'type': 'DnsConfig'},
        'monitor_config': {'key': 'properties.monitorConfig', 'type': 'MonitorConfig'},
        'endpoints': {'key': 'properties.endpoints', 'type': '[Endpoint]'},
        'traffic_view_enrollment_status': {'key': 'properties.trafficViewEnrollmentStatus', 'type': 'str'},
        'max_return': {'key': 'properties.maxReturn', 'type': 'long'},
    }

    def __init__(self, *, id: str=None, name: str=None, type: str=None, tags=None, location: str=None, profile_status=None, traffic_routing_method=None, dns_config=None, monitor_config=None, endpoints=None, traffic_view_enrollment_status=None, max_return: int=None, **kwargs) -> None:
        super(Profile, self).__init__(id=id, name=name, type=type, tags=tags, location=location, **kwargs)
        self.profile_status = profile_status
        self.traffic_routing_method = traffic_routing_method
        self.dns_config = dns_config
        self.monitor_config = monitor_config
        self.endpoints = endpoints
        self.traffic_view_enrollment_status = traffic_view_enrollment_status
        self.max_return = max_return
