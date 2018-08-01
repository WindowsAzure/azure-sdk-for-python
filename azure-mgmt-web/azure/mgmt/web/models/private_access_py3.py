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


class PrivateAccess(ProxyOnlyResource):
    """Description of the parameters of Private Access for a Web Site.

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
    :param enabled: Whether private access is enabled or not.
    :type enabled: bool
    :param virtual_networks: The Virtual Networks (and subnets) allowed to
     access the site privately.
    :type virtual_networks:
     list[~azure.mgmt.web.models.PrivateAccessVirtualNetwork]
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
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'virtual_networks': {'key': 'properties.virtualNetworks', 'type': '[PrivateAccessVirtualNetwork]'},
    }

    def __init__(self, *, kind: str=None, enabled: bool=None, virtual_networks=None, **kwargs) -> None:
        super(PrivateAccess, self).__init__(kind=kind, **kwargs)
        self.enabled = enabled
        self.virtual_networks = virtual_networks
