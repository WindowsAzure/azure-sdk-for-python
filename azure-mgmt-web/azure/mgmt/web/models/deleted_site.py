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


class DeletedSite(Model):
    """A deleted app.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Numeric id for the deleted site
    :type id: int
    :ivar deleted_timestamp: Time in UTC when the app was deleted.
    :vartype deleted_timestamp: str
    :ivar subscription: Subscription containing the deleted site
    :vartype subscription: str
    :ivar resource_group: ResourceGroup that contained the deleted site
    :vartype resource_group: str
    :ivar name: Name of the deleted site
    :vartype name: str
    """

    _validation = {
        'deleted_timestamp': {'readonly': True},
        'subscription': {'readonly': True},
        'resource_group': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'int'},
        'deleted_timestamp': {'key': 'deletedTimestamp', 'type': 'str'},
        'subscription': {'key': 'subscription', 'type': 'str'},
        'resource_group': {'key': 'resourceGroup', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, id=None):
        self.id = id
        self.deleted_timestamp = None
        self.subscription = None
        self.resource_group = None
        self.name = None
