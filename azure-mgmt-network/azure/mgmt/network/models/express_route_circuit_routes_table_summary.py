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


class ExpressRouteCircuitRoutesTableSummary(Model):
    """The routes table associated with the ExpressRouteCircuit.

    :param neighbor: Neighbor.
    :type neighbor: str
    :param v: BGP version number spoken to the neighbor.
    :type v: int
    :param as_property: Autonomous system number.
    :type as_property: int
    :param up_down: The length of time that the BGP session has been in the
     Established state, or the current status if not in the Established state.
    :type up_down: str
    :param state_pfx_rcd: Current state of the BGP session, and the number of
     prefixes that have been received from a neighbor or peer group.
    :type state_pfx_rcd: str
    """ 

    _attribute_map = {
        'neighbor': {'key': 'neighbor', 'type': 'str'},
        'v': {'key': 'v', 'type': 'int'},
        'as_property': {'key': 'as', 'type': 'int'},
        'up_down': {'key': 'upDown', 'type': 'str'},
        'state_pfx_rcd': {'key': 'statePfxRcd', 'type': 'str'},
    }

    def __init__(self, neighbor=None, v=None, as_property=None, up_down=None, state_pfx_rcd=None):
        self.neighbor = neighbor
        self.v = v
        self.as_property = as_property
        self.up_down = up_down
        self.state_pfx_rcd = state_pfx_rcd
