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

from .sub_resource import SubResource


class NetworkInterfaceTapConfiguration(SubResource):
    """Tap configuration in a Network Interface.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param virtual_network_tap: The reference of the Virtual Network Tap
     resource.
    :type virtual_network_tap:
     ~azure.mgmt.network.v2018_08_01.models.VirtualNetworkTap
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    :ivar type: Sub Resource type.
    :vartype type: str
    """

    _validation = {
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'virtual_network_tap': {'key': 'properties.virtualNetworkTap', 'type': 'VirtualNetworkTap'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(NetworkInterfaceTapConfiguration, self).__init__(**kwargs)
        self.virtual_network_tap = kwargs.get('virtual_network_tap', None)
        self.name = kwargs.get('name', None)
        self.etag = kwargs.get('etag', None)
        self.type = None
