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


class ManagedDatabaseUpdate(Model):
    """An managed database update.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param collation: Collation of the managed database.
    :type collation: str
    :ivar status: Status for the database. Possible values include: 'Online',
     'Offline', 'Shutdown', 'Creating', 'Inaccessible'
    :vartype status: str or ~azure.mgmt.sql.models.ManagedDatabaseStatus
    :ivar creation_date: Creation date of the database.
    :vartype creation_date: datetime
    :ivar default_secondary_location: Geo paired region.
    :vartype default_secondary_location: str
    :param catalog_collation: Collation of the metadata catalog. Possible
     values include: 'DATABASE_DEFAULT', 'SQL_Latin1_General_CP1_CI_AS'
    :type catalog_collation: str or
     ~azure.mgmt.sql.models.CatalogCollationType
    :param create_mode: Managed database create mode. PointInTimeRestore:
     Create a database by restoring a point in time backup of an existing
     database. SourceDatabaseName, SourceManagedInstanceName and PointInTime
     must be specified. RestoreExternalBackup: Create a database by restoring
     from external backup files. Collation, StorageContainerUri and
     StorageContainerSasToken must be specified. Possible values include:
     'Default', 'RestoreExternalBackup', 'PointInTimeRestore'
    :type create_mode: str or ~azure.mgmt.sql.models.ManagedDatabaseCreateMode
    :param restore_point_in_time: Conditional. If createMode is
     PointInTimeRestore, this value is required. Specifies the point in time
     (ISO8601 format) of the source database that will be restored to create
     the new database.
    :type restore_point_in_time: datetime
    :param source_database_id: The resource identifier of the source database
     associated with create operation of this database.
    :type source_database_id: str
    :param storage_container_uri: Conditional. If createMode is
     RestoreExternalBackup, this value is required. Specifies the uri of the
     storage container where backups for this restore are stored.
    :type storage_container_uri: str
    :param storage_container_sas_token: Conditional. If createMode is
     RestoreExternalBackup, this value is required. Specifies the storage
     container sas token.
    :type storage_container_sas_token: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'status': {'readonly': True},
        'creation_date': {'readonly': True},
        'default_secondary_location': {'readonly': True},
    }

    _attribute_map = {
        'collation': {'key': 'properties.collation', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'creation_date': {'key': 'properties.creationDate', 'type': 'iso-8601'},
        'default_secondary_location': {'key': 'properties.defaultSecondaryLocation', 'type': 'str'},
        'catalog_collation': {'key': 'properties.catalogCollation', 'type': 'str'},
        'create_mode': {'key': 'properties.createMode', 'type': 'str'},
        'restore_point_in_time': {'key': 'properties.restorePointInTime', 'type': 'iso-8601'},
        'source_database_id': {'key': 'properties.sourceDatabaseId', 'type': 'str'},
        'storage_container_uri': {'key': 'properties.storageContainerUri', 'type': 'str'},
        'storage_container_sas_token': {'key': 'properties.storageContainerSasToken', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, collation=None, catalog_collation=None, create_mode=None, restore_point_in_time=None, source_database_id=None, storage_container_uri=None, storage_container_sas_token=None, tags=None):
        self.collation = collation
        self.status = None
        self.creation_date = None
        self.default_secondary_location = None
        self.catalog_collation = catalog_collation
        self.create_mode = create_mode
        self.restore_point_in_time = restore_point_in_time
        self.source_database_id = source_database_id
        self.storage_container_uri = storage_container_uri
        self.storage_container_sas_token = storage_container_sas_token
        self.tags = tags
