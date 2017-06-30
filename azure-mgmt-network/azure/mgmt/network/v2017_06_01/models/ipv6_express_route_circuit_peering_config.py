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


class Ipv6ExpressRouteCircuitPeeringConfig(Model):
    """Contains IPv6 peering config.

    :param primary_peer_address_prefix: The primary address prefix.
    :type primary_peer_address_prefix: str
    :param secondary_peer_address_prefix: The secondary address prefix.
    :type secondary_peer_address_prefix: str
    :param microsoft_peering_config: The Microsoft peering configuration.
    :type microsoft_peering_config: :class:`ExpressRouteCircuitPeeringConfig
     <azure.mgmt.network.v2017_06_01.models.ExpressRouteCircuitPeeringConfig>`
    :param route_filter: The reference of the RouteFilter resource.
    :type route_filter: :class:`RouteFilter
     <azure.mgmt.network.v2017_06_01.models.RouteFilter>`
    :param state: The state of peering. Possible values are: 'Disabled' and
     'Enabled'. Possible values include: 'Disabled', 'Enabled'
    :type state: str or :class:`ExpressRouteCircuitPeeringState
     <azure.mgmt.network.v2017_06_01.models.ExpressRouteCircuitPeeringState>`
    """

    _attribute_map = {
        'primary_peer_address_prefix': {'key': 'primaryPeerAddressPrefix', 'type': 'str'},
        'secondary_peer_address_prefix': {'key': 'secondaryPeerAddressPrefix', 'type': 'str'},
        'microsoft_peering_config': {'key': 'microsoftPeeringConfig', 'type': 'ExpressRouteCircuitPeeringConfig'},
        'route_filter': {'key': 'routeFilter', 'type': 'RouteFilter'},
        'state': {'key': 'state', 'type': 'str'},
    }

    def __init__(self, primary_peer_address_prefix=None, secondary_peer_address_prefix=None, microsoft_peering_config=None, route_filter=None, state=None):
        self.primary_peer_address_prefix = primary_peer_address_prefix
        self.secondary_peer_address_prefix = secondary_peer_address_prefix
        self.microsoft_peering_config = microsoft_peering_config
        self.route_filter = route_filter
        self.state = state
