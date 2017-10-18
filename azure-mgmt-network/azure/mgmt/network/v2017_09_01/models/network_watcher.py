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


class NetworkWatcher(Resource):
    """Network watcher in a resource group.

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
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    :ivar provisioning_state: The provisioning state of the resource. Possible
     values include: 'Succeeded', 'Updating', 'Deleting', 'Failed'
    :vartype provisioning_state: str or
     ~azure.mgmt.network.v2017_09_01.models.ProvisioningState
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'etag': {'key': 'etag', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, id=None, location=None, tags=None, etag=None):
        super(NetworkWatcher, self).__init__(id=id, location=location, tags=tags)
        self.etag = etag
        self.provisioning_state = None
