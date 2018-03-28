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


class ValidateMigrationInputSqlServerSqlMITaskOutput(Model):
    """Output for task that validates migration input for SQL to Azure SQL Managed
    Instance migrations.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Result identifier
    :vartype id: str
    :ivar name: Name of database
    :vartype name: str
    :ivar restore_database_name_errors: Errors associated with the
     RestoreDatabaseName
    :vartype restore_database_name_errors:
     list[~azure.mgmt.datamigration.models.ReportableException]
    :ivar backup_folder_errors: Errors associated with the BackupFolder path
    :vartype backup_folder_errors:
     list[~azure.mgmt.datamigration.models.ReportableException]
    :ivar backup_share_credentials_errors: Errors associated with backup share
     user name and password credentials
    :vartype backup_share_credentials_errors:
     list[~azure.mgmt.datamigration.models.ReportableException]
    :ivar backup_storage_account_errors: Errors associated with the storage
     account provided.
    :vartype backup_storage_account_errors:
     list[~azure.mgmt.datamigration.models.ReportableException]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'restore_database_name_errors': {'readonly': True},
        'backup_folder_errors': {'readonly': True},
        'backup_share_credentials_errors': {'readonly': True},
        'backup_storage_account_errors': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'restore_database_name_errors': {'key': 'restoreDatabaseNameErrors', 'type': '[ReportableException]'},
        'backup_folder_errors': {'key': 'backupFolderErrors', 'type': '[ReportableException]'},
        'backup_share_credentials_errors': {'key': 'backupShareCredentialsErrors', 'type': '[ReportableException]'},
        'backup_storage_account_errors': {'key': 'backupStorageAccountErrors', 'type': '[ReportableException]'},
    }

    def __init__(self, **kwargs):
        super(ValidateMigrationInputSqlServerSqlMITaskOutput, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.restore_database_name_errors = None
        self.backup_folder_errors = None
        self.backup_share_credentials_errors = None
        self.backup_storage_account_errors = None
