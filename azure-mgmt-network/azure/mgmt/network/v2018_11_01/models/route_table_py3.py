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

from .resource_py3 import Resource


class RouteTable(Resource):
    """Route table resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param routes: Collection of routes contained within a route table.
    :type routes: list[~azure.mgmt.network.v2018_11_01.models.Route]
    :ivar subnets: A collection of references to subnets.
    :vartype subnets: list[~azure.mgmt.network.v2018_11_01.models.Subnet]
    :param disable_bgp_route_propagation: Gets or sets whether to disable the
     routes learned by BGP on that route table. True means disable.
    :type disable_bgp_route_propagation: bool
    :param provisioning_state: The provisioning state of the resource.
     Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :type etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'subnets': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'routes': {'key': 'properties.routes', 'type': '[Route]'},
        'subnets': {'key': 'properties.subnets', 'type': '[Subnet]'},
        'disable_bgp_route_propagation': {'key': 'properties.disableBgpRoutePropagation', 'type': 'bool'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, location: str=None, tags=None, routes=None, disable_bgp_route_propagation: bool=None, provisioning_state: str=None, etag: str=None, **kwargs) -> None:
        super(RouteTable, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.routes = routes
        self.subnets = None
        self.disable_bgp_route_propagation = disable_bgp_route_propagation
        self.provisioning_state = provisioning_state
        self.etag = etag
