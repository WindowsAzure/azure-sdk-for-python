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


class VirtualHubRouteTable(Model):
    """VirtualHub route table.

    :param routes: List of all routes.
    :type routes: list[~azure.mgmt.network.v2019_02_01.models.VirtualHubRoute]
    """

    _attribute_map = {
        'routes': {'key': 'routes', 'type': '[VirtualHubRoute]'},
    }

    def __init__(self, *, routes=None, **kwargs) -> None:
        super(VirtualHubRouteTable, self).__init__(**kwargs)
        self.routes = routes
