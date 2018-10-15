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


class VirtualNetworkUsage(Model):
    """Usage details for subnet.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar current_value: Indicates number of IPs used from the Subnet.
    :vartype current_value: float
    :ivar id: Subnet identifier.
    :vartype id: str
    :ivar limit: Indicates the size of the subnet.
    :vartype limit: float
    :ivar name: The name containing common and localized value for usage.
    :vartype name:
     ~azure.mgmt.network.v2018_08_01.models.VirtualNetworkUsageName
    :ivar unit: Usage units. Returns 'Count'
    :vartype unit: str
    """

    _validation = {
        'current_value': {'readonly': True},
        'id': {'readonly': True},
        'limit': {'readonly': True},
        'name': {'readonly': True},
        'unit': {'readonly': True},
    }

    _attribute_map = {
        'current_value': {'key': 'currentValue', 'type': 'float'},
        'id': {'key': 'id', 'type': 'str'},
        'limit': {'key': 'limit', 'type': 'float'},
        'name': {'key': 'name', 'type': 'VirtualNetworkUsageName'},
        'unit': {'key': 'unit', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(VirtualNetworkUsage, self).__init__(**kwargs)
        self.current_value = None
        self.id = None
        self.limit = None
        self.name = None
        self.unit = None
