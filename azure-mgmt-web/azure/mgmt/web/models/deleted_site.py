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

    :param deleted_site_id: Numeric id for the deleted site
    :type deleted_site_id: int
    :ivar deleted_timestamp: Time in UTC when the app was deleted.
    :vartype deleted_timestamp: str
    :ivar subscription: Subscription containing the deleted site
    :vartype subscription: str
    :ivar resource_group: ResourceGroup that contained the deleted site
    :vartype resource_group: str
    :ivar deleted_site_name: Name of the deleted site
    :vartype deleted_site_name: str
    :ivar slot: Slot of the deleted site
    :vartype slot: str
    """

    _validation = {
        'deleted_timestamp': {'readonly': True},
        'subscription': {'readonly': True},
        'resource_group': {'readonly': True},
        'deleted_site_name': {'readonly': True},
        'slot': {'readonly': True},
    }

    _attribute_map = {
        'deleted_site_id': {'key': 'deletedSiteId', 'type': 'int'},
        'deleted_timestamp': {'key': 'deletedTimestamp', 'type': 'str'},
        'subscription': {'key': 'subscription', 'type': 'str'},
        'resource_group': {'key': 'resourceGroup', 'type': 'str'},
        'deleted_site_name': {'key': 'deletedSiteName', 'type': 'str'},
        'slot': {'key': 'slot', 'type': 'str'},
    }

    def __init__(self, deleted_site_id=None):
        super(DeletedSite, self).__init__()
        self.deleted_site_id = deleted_site_id
        self.deleted_timestamp = None
        self.subscription = None
        self.resource_group = None
        self.deleted_site_name = None
        self.slot = None
