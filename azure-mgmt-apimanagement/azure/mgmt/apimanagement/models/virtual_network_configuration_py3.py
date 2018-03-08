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


class VirtualNetworkConfiguration(Model):
    """Configuration of a virtual network to which API Management service is
    deployed.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar vnetid: The virtual network ID. This is typically a GUID. Expect a
     null GUID by default.
    :vartype vnetid: str
    :ivar subnetname: The name of the subnet.
    :vartype subnetname: str
    :param subnet_resource_id: The full resource ID of a subnet in a virtual
     network to deploy the API Management service in.
    :type subnet_resource_id: str
    """

    _validation = {
        'vnetid': {'readonly': True},
        'subnetname': {'readonly': True},
        'subnet_resource_id': {'pattern': r'^/subscriptions/[^/]*/resourceGroups/[^/]*/providers/Microsoft.(ClassicNetwork|Network)/virtualNetworks/[^/]*/subnets/[^/]*$'},
    }

    _attribute_map = {
        'vnetid': {'key': 'vnetid', 'type': 'str'},
        'subnetname': {'key': 'subnetname', 'type': 'str'},
        'subnet_resource_id': {'key': 'subnetResourceId', 'type': 'str'},
    }

    def __init__(self, *, subnet_resource_id: str=None, **kwargs) -> None:
        super(VirtualNetworkConfiguration, self).__init__(**kwargs)
        self.vnetid = None
        self.subnetname = None
        self.subnet_resource_id = subnet_resource_id
