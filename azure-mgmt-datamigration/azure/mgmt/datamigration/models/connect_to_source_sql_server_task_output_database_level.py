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

from .connect_to_source_sql_server_task_output import ConnectToSourceSqlServerTaskOutput


class ConnectToSourceSqlServerTaskOutputDatabaseLevel(ConnectToSourceSqlServerTaskOutput):
    """Database level output for the task that validates connection to SQL Server
    and also validates source server requirements.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Result identifier
    :vartype id: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    :ivar name: Database name
    :vartype name: str
    :ivar size_mb: Size of the file in megabytes
    :vartype size_mb: float
    :ivar database_files: The list of database files
    :vartype database_files:
     list[~azure.mgmt.datamigration.models.DatabaseFileInfo]
    :ivar compatibility_level: SQL Server compatibility level of database.
     Possible values include: 'CompatLevel80', 'CompatLevel90',
     'CompatLevel100', 'CompatLevel110', 'CompatLevel120', 'CompatLevel130',
     'CompatLevel140'
    :vartype compatibility_level: str or
     ~azure.mgmt.datamigration.models.DatabaseCompatLevel
    :ivar database_state: State of the database. Possible values include:
     'Online', 'Restoring', 'Recovering', 'RecoveryPending', 'Suspect',
     'Emergency', 'Offline', 'Copying', 'OfflineSecondary'
    :vartype database_state: str or
     ~azure.mgmt.datamigration.models.DatabaseState
    """

    _validation = {
        'id': {'readonly': True},
        'result_type': {'required': True},
        'name': {'readonly': True},
        'size_mb': {'readonly': True},
        'database_files': {'readonly': True},
        'compatibility_level': {'readonly': True},
        'database_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'size_mb': {'key': 'sizeMB', 'type': 'float'},
        'database_files': {'key': 'databaseFiles', 'type': '[DatabaseFileInfo]'},
        'compatibility_level': {'key': 'compatibilityLevel', 'type': 'str'},
        'database_state': {'key': 'databaseState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ConnectToSourceSqlServerTaskOutputDatabaseLevel, self).__init__(**kwargs)
        self.name = None
        self.size_mb = None
        self.database_files = None
        self.compatibility_level = None
        self.database_state = None
        self.result_type = 'DatabaseLevelOutput'
