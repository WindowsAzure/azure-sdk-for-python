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


class GatewayRouteListResult(Model):
    """List of virtual network gateway routes.

    :param value: List of gateway routes
    :type value: list[~azure.mgmt.network.v2017_11_01.models.GatewayRoute]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[GatewayRoute]'},
    }

    def __init__(self, value=None):
        super(GatewayRouteListResult, self).__init__()
        self.value = value
