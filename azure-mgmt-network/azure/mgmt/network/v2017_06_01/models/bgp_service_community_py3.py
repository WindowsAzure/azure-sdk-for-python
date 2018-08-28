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


class BgpServiceCommunity(Resource):
    """Service Community Properties.

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
    :param service_name: The name of the bgp community. e.g. Skype.
    :type service_name: str
    :param bgp_communities: Get a list of bgp communities.
    :type bgp_communities:
     list[~azure.mgmt.network.v2017_06_01.models.BGPCommunity]
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'service_name': {'key': 'properties.serviceName', 'type': 'str'},
        'bgp_communities': {'key': 'properties.bgpCommunities', 'type': '[BGPCommunity]'},
    }

    def __init__(self, *, id: str=None, location: str=None, tags=None, service_name: str=None, bgp_communities=None, **kwargs) -> None:
        super(BgpServiceCommunity, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.service_name = service_name
        self.bgp_communities = bgp_communities
