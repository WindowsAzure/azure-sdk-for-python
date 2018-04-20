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

from .migrate_sql_server_sql_mi_task_output import MigrateSqlServerSqlMITaskOutput


class MigrateSqlServerSqlMITaskOutputDatabaseLevel(MigrateSqlServerSqlMITaskOutput):
    """MigrateSqlServerSqlMITaskOutputDatabaseLevel.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Result identifier
    :vartype id: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    :ivar database_name: Name of the database
    :vartype database_name: str
    :ivar size_mb: Size of the database in megabytes
    :vartype size_mb: float
    :ivar state: Current state of migration. Possible values include: 'None',
     'InProgress', 'Failed', 'Warning', 'Completed', 'Skipped', 'Stopped'
    :vartype state: str or ~azure.mgmt.datamigration.models.MigrationState
    :ivar stage: Current stage of migration. Possible values include: 'None',
     'Initialize', 'Backup', 'FileCopy', 'Restore', 'Completed'
    :vartype stage: str or
     ~azure.mgmt.datamigration.models.DatabaseMigrationStage
    :ivar started_on: Migration start time
    :vartype started_on: datetime
    :ivar ended_on: Migration end time
    :vartype ended_on: datetime
    :ivar message: Migration progress message
    :vartype message: str
    :ivar exceptions_and_warnings: Migration exceptions and warnings
    :vartype exceptions_and_warnings:
     list[~azure.mgmt.datamigration.models.ReportableException]
    """

    _validation = {
        'id': {'readonly': True},
        'result_type': {'required': True},
        'database_name': {'readonly': True},
        'size_mb': {'readonly': True},
        'state': {'readonly': True},
        'stage': {'readonly': True},
        'started_on': {'readonly': True},
        'ended_on': {'readonly': True},
        'message': {'readonly': True},
        'exceptions_and_warnings': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
        'database_name': {'key': 'databaseName', 'type': 'str'},
        'size_mb': {'key': 'sizeMB', 'type': 'float'},
        'state': {'key': 'state', 'type': 'str'},
        'stage': {'key': 'stage', 'type': 'str'},
        'started_on': {'key': 'startedOn', 'type': 'iso-8601'},
        'ended_on': {'key': 'endedOn', 'type': 'iso-8601'},
        'message': {'key': 'message', 'type': 'str'},
        'exceptions_and_warnings': {'key': 'exceptionsAndWarnings', 'type': '[ReportableException]'},
    }

    def __init__(self, **kwargs) -> None:
        super(MigrateSqlServerSqlMITaskOutputDatabaseLevel, self).__init__(**kwargs)
        self.database_name = None
        self.size_mb = None
        self.state = None
        self.stage = None
        self.started_on = None
        self.ended_on = None
        self.message = None
        self.exceptions_and_warnings = None
        self.result_type = 'DatabaseLevelOutput'
