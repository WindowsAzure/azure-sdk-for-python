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


class ServiceTypeDeltaHealthPolicy(Model):
    """Represents the delta health policy used to evaluate the health of services
    belonging to a service type when upgrading the cluster.
    .

    :param max_percent_delta_unhealthy_services: The maximum allowed
     percentage of services health degradation allowed during cluster upgrades.
     The delta is measured between the state of the services at the beginning
     of upgrade and the state of the services at the time of the health
     evaluation.
     The check is performed after every upgrade domain upgrade completion to
     make sure the global state of the cluster is within tolerated limits.
     . Default value: 0 .
    :type max_percent_delta_unhealthy_services: int
    """

    _validation = {
        'max_percent_delta_unhealthy_services': {'maximum': 100, 'minimum': 0},
    }

    _attribute_map = {
        'max_percent_delta_unhealthy_services': {'key': 'maxPercentDeltaUnhealthyServices', 'type': 'int'},
    }

    def __init__(self, max_percent_delta_unhealthy_services=0):
        super(ServiceTypeDeltaHealthPolicy, self).__init__()
        self.max_percent_delta_unhealthy_services = max_percent_delta_unhealthy_services
