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

from .tracked_resource import TrackedResource


class ElasticPool(TrackedResource):
    """Represents a database elastic pool.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict
    :param location: Resource location.
    :type location: str
    :ivar creation_date: The creation date of the elastic pool (ISO8601
     format).
    :vartype creation_date: datetime
    :ivar state: The state of the elastic pool. Possible values include:
     'Creating', 'Ready', 'Disabled'
    :vartype state: str or :class:`ElasticPoolState
     <azure.mgmt.sql.models.ElasticPoolState>`
    :param edition: The edition of the elastic pool. Possible values include:
     'Basic', 'Standard', 'Premium'
    :type edition: str or :class:`ElasticPoolEdition
     <azure.mgmt.sql.models.ElasticPoolEdition>`
    :param dtu: The total shared DTU for the database elastic pool.
    :type dtu: int
    :param database_dtu_max: The maximum DTU any one database can consume.
    :type database_dtu_max: int
    :param database_dtu_min: The minimum DTU all databases are guaranteed.
    :type database_dtu_min: int
    :param storage_mb: Gets storage limit for the database elastic pool in MB.
    :type storage_mb: int
    :ivar kind: Kind of elastic pool.  This is metadata used for the Azure
     portal experience.
    :vartype kind: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'creation_date': {'readonly': True},
        'state': {'readonly': True},
        'kind': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'creation_date': {'key': 'properties.creationDate', 'type': 'iso-8601'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'edition': {'key': 'properties.edition', 'type': 'str'},
        'dtu': {'key': 'properties.dtu', 'type': 'int'},
        'database_dtu_max': {'key': 'properties.databaseDtuMax', 'type': 'int'},
        'database_dtu_min': {'key': 'properties.databaseDtuMin', 'type': 'int'},
        'storage_mb': {'key': 'properties.storageMB', 'type': 'int'},
        'kind': {'key': 'kind', 'type': 'str'},
    }

    def __init__(self, location, tags=None, edition=None, dtu=None, database_dtu_max=None, database_dtu_min=None, storage_mb=None):
        super(ElasticPool, self).__init__(tags=tags, location=location)
        self.creation_date = None
        self.state = None
        self.edition = edition
        self.dtu = dtu
        self.database_dtu_max = database_dtu_max
        self.database_dtu_min = database_dtu_min
        self.storage_mb = storage_mb
        self.kind = None
