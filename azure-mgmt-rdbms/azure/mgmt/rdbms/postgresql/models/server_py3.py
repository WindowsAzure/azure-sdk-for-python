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

from .tracked_resource_py3 import TrackedResource


class Server(TrackedResource):
    """Represents a server.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Required. The location the resource resides in.
    :type location: str
    :param tags: Application-specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :param sku: The SKU (pricing tier) of the server.
    :type sku: ~azure.mgmt.rdbms.postgresql.models.Sku
    :param administrator_login: The administrator's login name of a server.
     Can only be specified when the server is being created (and is required
     for creation).
    :type administrator_login: str
    :param version: Server version. Possible values include: '9.5', '9.6',
     '10', '10.0', '10.2'
    :type version: str or ~azure.mgmt.rdbms.postgresql.models.ServerVersion
    :param ssl_enforcement: Enable ssl enforcement or not when connect to
     server. Possible values include: 'Enabled', 'Disabled'
    :type ssl_enforcement: str or
     ~azure.mgmt.rdbms.postgresql.models.SslEnforcementEnum
    :param user_visible_state: A state of a server that is visible to user.
     Possible values include: 'Ready', 'Dropping', 'Disabled'
    :type user_visible_state: str or
     ~azure.mgmt.rdbms.postgresql.models.ServerState
    :param fully_qualified_domain_name: The fully qualified domain name of a
     server.
    :type fully_qualified_domain_name: str
    :param earliest_restore_date: Earliest restore point creation time
     (ISO8601 format)
    :type earliest_restore_date: datetime
    :param storage_profile: Storage profile of a server.
    :type storage_profile: ~azure.mgmt.rdbms.postgresql.models.StorageProfile
    :param replication_role: The replication role of the server.
    :type replication_role: str
    :param master_server_id: The master server id of a replica server.
    :type master_server_id: str
    :param replica_capacity: The maximum number of replicas that a master
     server can have.
    :type replica_capacity: int
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'replica_capacity': {'minimum': 0},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'administrator_login': {'key': 'properties.administratorLogin', 'type': 'str'},
        'version': {'key': 'properties.version', 'type': 'str'},
        'ssl_enforcement': {'key': 'properties.sslEnforcement', 'type': 'SslEnforcementEnum'},
        'user_visible_state': {'key': 'properties.userVisibleState', 'type': 'str'},
        'fully_qualified_domain_name': {'key': 'properties.fullyQualifiedDomainName', 'type': 'str'},
        'earliest_restore_date': {'key': 'properties.earliestRestoreDate', 'type': 'iso-8601'},
        'storage_profile': {'key': 'properties.storageProfile', 'type': 'StorageProfile'},
        'replication_role': {'key': 'properties.replicationRole', 'type': 'str'},
        'master_server_id': {'key': 'properties.masterServerId', 'type': 'str'},
        'replica_capacity': {'key': 'properties.replicaCapacity', 'type': 'int'},
    }

    def __init__(self, *, location: str, tags=None, sku=None, administrator_login: str=None, version=None, ssl_enforcement=None, user_visible_state=None, fully_qualified_domain_name: str=None, earliest_restore_date=None, storage_profile=None, replication_role: str=None, master_server_id: str=None, replica_capacity: int=None, **kwargs) -> None:
        super(Server, self).__init__(location=location, tags=tags, **kwargs)
        self.sku = sku
        self.administrator_login = administrator_login
        self.version = version
        self.ssl_enforcement = ssl_enforcement
        self.user_visible_state = user_visible_state
        self.fully_qualified_domain_name = fully_qualified_domain_name
        self.earliest_restore_date = earliest_restore_date
        self.storage_profile = storage_profile
        self.replication_role = replication_role
        self.master_server_id = master_server_id
        self.replica_capacity = replica_capacity
