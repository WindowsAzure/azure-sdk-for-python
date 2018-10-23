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

from .proxy_only_resource_py3 import ProxyOnlyResource


class VnetParameters(ProxyOnlyResource):
    """The required set of inputs to validate a VNET.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param vnet_resource_group: The Resource Group of the VNET to be validated
    :type vnet_resource_group: str
    :param vnet_name: The name of the VNET to be validated
    :type vnet_name: str
    :param vnet_subnet_name: The subnet name to be validated
    :type vnet_subnet_name: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'vnet_resource_group': {'key': 'properties.vnetResourceGroup', 'type': 'str'},
        'vnet_name': {'key': 'properties.vnetName', 'type': 'str'},
        'vnet_subnet_name': {'key': 'properties.vnetSubnetName', 'type': 'str'},
    }

    def __init__(self, *, kind: str=None, vnet_resource_group: str=None, vnet_name: str=None, vnet_subnet_name: str=None, **kwargs) -> None:
        super(VnetParameters, self).__init__(kind=kind, **kwargs)
        self.vnet_resource_group = vnet_resource_group
        self.vnet_name = vnet_name
        self.vnet_subnet_name = vnet_subnet_name
