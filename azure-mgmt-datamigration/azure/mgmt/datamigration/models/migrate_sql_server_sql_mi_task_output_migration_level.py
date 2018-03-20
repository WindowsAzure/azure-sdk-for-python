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


class MigrateSqlServerSqlMITaskOutputMigrationLevel(MigrateSqlServerSqlMITaskOutput):
    """MigrateSqlServerSqlMITaskOutputMigrationLevel.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Result identifier
    :vartype id: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    :ivar started_on: Migration start time
    :vartype started_on: datetime
    :ivar ended_on: Migration end time
    :vartype ended_on: datetime
    :ivar status: Current status of migration. Possible values include:
     'Default', 'Connecting', 'SourceAndTargetSelected', 'SelectLogins',
     'Configured', 'Running', 'Error', 'Stopped', 'Completed',
     'CompletedWithWarnings'
    :vartype status: str or ~azure.mgmt.datamigration.models.MigrationStatus
    :ivar state: Current state of migration. Possible values include: 'None',
     'InProgress', 'Failed', 'Warning', 'Completed', 'Skipped', 'Stopped'
    :vartype state: str or ~azure.mgmt.datamigration.models.MigrationState
    :ivar message: Migration progress message
    :vartype message: str
    :ivar databases: Selected databases as a map from database name to
     database id
    :vartype databases: dict[str, str]
    :ivar source_server_version: Source server version
    :vartype source_server_version: str
    :ivar source_server_brand_version: Source server brand version
    :vartype source_server_brand_version: str
    :ivar target_server_version: Target server version
    :vartype target_server_version: str
    :ivar target_server_brand_version: Target server brand version
    :vartype target_server_brand_version: str
    :ivar exceptions_and_warnings: Migration exceptions and warnings.
    :vartype exceptions_and_warnings:
     list[~azure.mgmt.datamigration.models.ReportableException]
    """

    _validation = {
        'id': {'readonly': True},
        'result_type': {'required': True},
        'started_on': {'readonly': True},
        'ended_on': {'readonly': True},
        'status': {'readonly': True},
        'state': {'readonly': True},
        'message': {'readonly': True},
        'databases': {'readonly': True},
        'source_server_version': {'readonly': True},
        'source_server_brand_version': {'readonly': True},
        'target_server_version': {'readonly': True},
        'target_server_brand_version': {'readonly': True},
        'exceptions_and_warnings': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
        'started_on': {'key': 'startedOn', 'type': 'iso-8601'},
        'ended_on': {'key': 'endedOn', 'type': 'iso-8601'},
        'status': {'key': 'status', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'databases': {'key': 'databases', 'type': '{str}'},
        'source_server_version': {'key': 'sourceServerVersion', 'type': 'str'},
        'source_server_brand_version': {'key': 'sourceServerBrandVersion', 'type': 'str'},
        'target_server_version': {'key': 'targetServerVersion', 'type': 'str'},
        'target_server_brand_version': {'key': 'targetServerBrandVersion', 'type': 'str'},
        'exceptions_and_warnings': {'key': 'exceptionsAndWarnings', 'type': '[ReportableException]'},
    }

    def __init__(self, **kwargs):
        super(MigrateSqlServerSqlMITaskOutputMigrationLevel, self).__init__(**kwargs)
        self.started_on = None
        self.ended_on = None
        self.status = None
        self.state = None
        self.message = None
        self.databases = None
        self.source_server_version = None
        self.source_server_brand_version = None
        self.target_server_version = None
        self.target_server_brand_version = None
        self.exceptions_and_warnings = None
        self.result_type = 'MigrationLevelOutput'
