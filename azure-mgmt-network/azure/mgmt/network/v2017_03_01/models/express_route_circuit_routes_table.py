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


class ExpressRouteCircuitRoutesTable(Model):
    """The routes table associated with the ExpressRouteCircuit.

    :param network: network
    :type network: str
    :param next_hop: nextHop
    :type next_hop: str
    :param loc_prf: locPrf
    :type loc_prf: str
    :param weight: weight.
    :type weight: int
    :param path: path
    :type path: str
    """

    _attribute_map = {
        'network': {'key': 'network', 'type': 'str'},
        'next_hop': {'key': 'nextHop', 'type': 'str'},
        'loc_prf': {'key': 'locPrf', 'type': 'str'},
        'weight': {'key': 'weight', 'type': 'int'},
        'path': {'key': 'path', 'type': 'str'},
    }

    def __init__(self, network=None, next_hop=None, loc_prf=None, weight=None, path=None):
        self.network = network
        self.next_hop = next_hop
        self.loc_prf = loc_prf
        self.weight = weight
        self.path = path
