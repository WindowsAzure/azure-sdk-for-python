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


class DeployedServicePackageHealthStateFilter(Model):
    """Defines matching criteria to determine whether a deployed service package
    should be included as a child of a deployed application in the cluster
    health chunk.
    The deployed service packages are only returned if the parent entities
    match a filter specified in the cluster health chunk query description. The
    parent deployed application and its parent application must be included in
    the cluster health chunk.
    One filter can match zero, one or multiple deployed service packages,
    depending on its properties.
    .

    :param service_manifest_name_filter: The name of the service manifest
     which identifies the deployed service packages that matches the filter.
     If specified, the filter is applied only to the specified deployed service
     packages, if any.
     If no deployed service packages with specified manifest name exist,
     nothing is returned in the cluster health chunk based on this filter.
     If any deployed service package exists, they are included in the cluster
     health chunk if it respects the other filter properties.
     If not specified, all deployed service packages that match the parent
     filters (if any) are taken into consideration and matched against the
     other filter members, like health state filter.
    :type service_manifest_name_filter: str
    :param service_package_activation_id_filter: The activation ID of a
     deployed service package that matches the filter.
     If not specified, the filter applies to all deployed service packages that
     match the other parameters.
     If specified, the filter matches only the deployed service package with
     the specified activation ID.
    :type service_package_activation_id_filter: str
    :param health_state_filter: The filter for the health state of the
     deployed service packages. It allows selecting deployed service packages
     if they match the desired health states.
     The possible values are integer value of one of the following health
     states. Only deployed service packages that match the filter are returned.
     All deployed service packages are used to evaluate the parent deployed
     application aggregated health state.
     If not specified, default value is None, unless the deployed service
     package id is specified. If the filter has default value and deployed
     service package id is specified, the matching deployed service package is
     returned.
     The state values are flag based enumeration, so the value could be a
     combination of these values obtained using bitwise 'OR' operator.
     For example, if the provided value is 6, it matches deployed service
     packages with HealthState value of OK (2) and Warning (4).
     - Default - Default value. Matches any HealthState. The value is zero.
     - None - Filter that doesn't match any HealthState value. Used in order to
     return no results on a given collection of states. The value is 1.
     - Ok - Filter that matches input with HealthState value Ok. The value is
     2.
     - Warning - Filter that matches input with HealthState value Warning. The
     value is 4.
     - Error - Filter that matches input with HealthState value Error. The
     value is 8.
     - All - Filter that matches input with any HealthState value. The value is
     65535.
     . Default value: 0 .
    :type health_state_filter: int
    """

    _attribute_map = {
        'service_manifest_name_filter': {'key': 'ServiceManifestNameFilter', 'type': 'str'},
        'service_package_activation_id_filter': {'key': 'ServicePackageActivationIdFilter', 'type': 'str'},
        'health_state_filter': {'key': 'HealthStateFilter', 'type': 'int'},
    }

    def __init__(self, service_manifest_name_filter=None, service_package_activation_id_filter=None, health_state_filter=0):
        super(DeployedServicePackageHealthStateFilter, self).__init__()
        self.service_manifest_name_filter = service_manifest_name_filter
        self.service_package_activation_id_filter = service_package_activation_id_filter
        self.health_state_filter = health_state_filter
