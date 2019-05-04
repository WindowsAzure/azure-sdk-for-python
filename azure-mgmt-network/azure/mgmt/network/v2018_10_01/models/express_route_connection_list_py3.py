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


class ExpressRouteConnectionList(Model):
    """ExpressRouteConnection list.

    :param value: The list of ExpressRoute connections
    :type value:
     list[~azure.mgmt.network.v2018_10_01.models.ExpressRouteConnection]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ExpressRouteConnection]'},
    }

    def __init__(self, *, value=None, **kwargs) -> None:
        super(ExpressRouteConnectionList, self).__init__(**kwargs)
        self.value = value
