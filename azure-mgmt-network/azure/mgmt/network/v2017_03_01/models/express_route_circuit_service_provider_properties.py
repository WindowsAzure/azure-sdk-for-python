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


class ExpressRouteCircuitServiceProviderProperties(Model):
    """Contains ServiceProviderProperties in an ExpressRouteCircuit.

    :param service_provider_name: The serviceProviderName.
    :type service_provider_name: str
    :param peering_location: The peering location.
    :type peering_location: str
    :param bandwidth_in_mbps: The BandwidthInMbps.
    :type bandwidth_in_mbps: int
    """

    _attribute_map = {
        'service_provider_name': {'key': 'serviceProviderName', 'type': 'str'},
        'peering_location': {'key': 'peeringLocation', 'type': 'str'},
        'bandwidth_in_mbps': {'key': 'bandwidthInMbps', 'type': 'int'},
    }

    def __init__(self, service_provider_name=None, peering_location=None, bandwidth_in_mbps=None):
        super(ExpressRouteCircuitServiceProviderProperties, self).__init__()
        self.service_provider_name = service_provider_name
        self.peering_location = peering_location
        self.bandwidth_in_mbps = bandwidth_in_mbps
