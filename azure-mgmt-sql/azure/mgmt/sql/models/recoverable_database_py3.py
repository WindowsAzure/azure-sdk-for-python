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

from .proxy_resource_py3 import ProxyResource


class RecoverableDatabase(ProxyResource):
    """A recoverable database.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar edition: The edition of the database
    :vartype edition: str
    :ivar service_level_objective: The service level objective name of the
     database
    :vartype service_level_objective: str
    :ivar elastic_pool_name: The elastic pool name of the database
    :vartype elastic_pool_name: str
    :ivar last_available_backup_date: The last available backup date of the
     database (ISO8601 format)
    :vartype last_available_backup_date: datetime
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'edition': {'readonly': True},
        'service_level_objective': {'readonly': True},
        'elastic_pool_name': {'readonly': True},
        'last_available_backup_date': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'edition': {'key': 'properties.edition', 'type': 'str'},
        'service_level_objective': {'key': 'properties.serviceLevelObjective', 'type': 'str'},
        'elastic_pool_name': {'key': 'properties.elasticPoolName', 'type': 'str'},
        'last_available_backup_date': {'key': 'properties.lastAvailableBackupDate', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs) -> None:
        super(RecoverableDatabase, self).__init__(**kwargs)
        self.edition = None
        self.service_level_objective = None
        self.elastic_pool_name = None
        self.last_available_backup_date = None
