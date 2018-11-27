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


class PatchRouteFilter(SubResource):
    """Route Filter Resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param rules: Collection of RouteFilterRules contained within a route
     filter.
    :type rules: list[~azure.mgmt.network.v2018_10_01.models.RouteFilterRule]
    :param peerings: A collection of references to express route circuit
     peerings.
    :type peerings:
     list[~azure.mgmt.network.v2018_10_01.models.ExpressRouteCircuitPeering]
    :ivar provisioning_state: The provisioning state of the resource. Possible
     values are: 'Updating', 'Deleting', 'Succeeded' and 'Failed'.
    :vartype provisioning_state: str
    :ivar name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :vartype name: str
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :ivar type: Resource type.
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'name': {'readonly': True},
        'etag': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'rules': {'key': 'properties.rules', 'type': '[RouteFilterRule]'},
        'peerings': {'key': 'properties.peerings', 'type': '[ExpressRouteCircuitPeering]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(PatchRouteFilter, self).__init__(**kwargs)
        self.rules = kwargs.get('rules', None)
        self.peerings = kwargs.get('peerings', None)
        self.provisioning_state = None
        self.name = None
        self.etag = None
        self.type = None
        self.tags = kwargs.get('tags', None)
