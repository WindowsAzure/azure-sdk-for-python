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

from .proxy_resource import ProxyResource


class SyncAgent(ProxyResource):
    """An Azure SQL Database sync agent.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar sync_agent_name: Name of the sync agent.
    :vartype sync_agent_name: str
    :param sync_database_id: ARM resource id of the sync database in the sync
     agent.
    :type sync_database_id: str
    :ivar last_alive_time: Last alive time of the sync agent.
    :vartype last_alive_time: datetime
    :ivar state: State of the sync agent. Possible values include: 'Online',
     'Offline', 'NeverConnected'
    :vartype state: str or ~azure.mgmt.sql.models.SyncAgentState
    :ivar is_up_to_date: If the sync agent version is up to date.
    :vartype is_up_to_date: bool
    :ivar expiry_time: Expiration time of the sync agent version.
    :vartype expiry_time: datetime
    :ivar version: Version of the sync agent.
    :vartype version: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'sync_agent_name': {'readonly': True},
        'last_alive_time': {'readonly': True},
        'state': {'readonly': True},
        'is_up_to_date': {'readonly': True},
        'expiry_time': {'readonly': True},
        'version': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'sync_agent_name': {'key': 'properties.name', 'type': 'str'},
        'sync_database_id': {'key': 'properties.syncDatabaseId', 'type': 'str'},
        'last_alive_time': {'key': 'properties.lastAliveTime', 'type': 'iso-8601'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'is_up_to_date': {'key': 'properties.isUpToDate', 'type': 'bool'},
        'expiry_time': {'key': 'properties.expiryTime', 'type': 'iso-8601'},
        'version': {'key': 'properties.version', 'type': 'str'},
    }

    def __init__(self, *, sync_database_id: str=None, **kwargs) -> None:
        super(SyncAgent, self).__init__(**kwargs)
        self.sync_agent_name = None
        self.sync_database_id = sync_database_id
        self.last_alive_time = None
        self.state = None
        self.is_up_to_date = None
        self.expiry_time = None
        self.version = None
