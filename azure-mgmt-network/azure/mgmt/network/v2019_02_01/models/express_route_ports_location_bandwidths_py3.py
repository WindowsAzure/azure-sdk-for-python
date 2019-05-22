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


class ExpressRoutePortsLocationBandwidths(Model):
    """ExpressRoutePorts Location Bandwidths.

    Real-time inventory of available ExpressRoute port bandwidths.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar offer_name: Bandwidth descriptive name
    :vartype offer_name: str
    :ivar value_in_gbps: Bandwidth value in Gbps
    :vartype value_in_gbps: int
    """

    _validation = {
        'offer_name': {'readonly': True},
        'value_in_gbps': {'readonly': True},
    }

    _attribute_map = {
        'offer_name': {'key': 'offerName', 'type': 'str'},
        'value_in_gbps': {'key': 'valueInGbps', 'type': 'int'},
    }

    def __init__(self, **kwargs) -> None:
        super(ExpressRoutePortsLocationBandwidths, self).__init__(**kwargs)
        self.offer_name = None
        self.value_in_gbps = None
