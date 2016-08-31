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

from .resource import Resource


class RouteTable(Resource):
    """RouteTable resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource Id
    :type id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param routes: Gets or sets Routes in a Route Table
    :type routes: list of :class:`Route <azure.mgmt.network.models.Route>`
    :ivar subnets: Gets collection of references to subnets
    :vartype subnets: list of :class:`Subnet
     <azure.mgmt.network.models.Subnet>`
    :param provisioning_state: Gets provisioning state of the resource
     Updating/Deleting/Failed
    :type provisioning_state: str
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated
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
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, location=None, tags=None, routes=None, provisioning_state=None, etag=None):
        super(RouteTable, self).__init__(id=id, location=location, tags=tags)
        self.routes = routes
        self.subnets = None
        self.provisioning_state = provisioning_state
        self.etag = etag
