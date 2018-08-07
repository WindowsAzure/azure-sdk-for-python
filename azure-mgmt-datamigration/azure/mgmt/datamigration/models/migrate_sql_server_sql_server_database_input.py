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


class MigrateSqlServerSqlServerDatabaseInput(Model):
    """Database specific information for SQL to SQL migration task inputs.

    :param name: Name of the database
    :type name: str
    :param restore_database_name: Name of the database at destination
    :type restore_database_name: str
    :param backup_file_share: Backup file share information for this database.
    :type backup_file_share: ~azure.mgmt.datamigration.models.FileShare
    :param database_files: The list of database files
    :type database_files:
     list[~azure.mgmt.datamigration.models.DatabaseFileInput]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'restore_database_name': {'key': 'restoreDatabaseName', 'type': 'str'},
        'backup_file_share': {'key': 'backupFileShare', 'type': 'FileShare'},
        'database_files': {'key': 'databaseFiles', 'type': '[DatabaseFileInput]'},
    }

    def __init__(self, **kwargs):
        super(MigrateSqlServerSqlServerDatabaseInput, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.restore_database_name = kwargs.get('restore_database_name', None)
        self.backup_file_share = kwargs.get('backup_file_share', None)
        self.database_files = kwargs.get('database_files', None)
