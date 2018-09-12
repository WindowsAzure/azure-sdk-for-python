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

from .migrate_postgre_sql_azure_db_for_postgre_sql_sync_task_output_py3 import MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutput


class MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutputDatabaseLevel(MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutput):
    """MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutputDatabaseLevel.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Result identifier
    :vartype id: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    :ivar database_name: Name of the database
    :vartype database_name: str
    :ivar started_on: Migration start time
    :vartype started_on: datetime
    :ivar ended_on: Migration end time
    :vartype ended_on: datetime
    :ivar migration_state: Migration state that this database is in. Possible
     values include: 'UNDEFINED', 'CONFIGURING', 'INITIALIAZING', 'STARTING',
     'RUNNING', 'READY_TO_COMPLETE', 'COMPLETING', 'COMPLETE', 'CANCELLING',
     'CANCELLED', 'FAILED'
    :vartype migration_state: str or
     ~azure.mgmt.datamigration.models.SyncDatabaseMigrationReportingState
    :ivar incoming_changes: Number of incoming changes
    :vartype incoming_changes: long
    :ivar applied_changes: Number of applied changes
    :vartype applied_changes: long
    :ivar cdc_insert_counter: Number of cdc inserts
    :vartype cdc_insert_counter: long
    :ivar cdc_delete_counter: Number of cdc deletes
    :vartype cdc_delete_counter: long
    :ivar cdc_update_counter: Number of cdc updates
    :vartype cdc_update_counter: long
    :ivar full_load_completed_tables: Number of tables completed in full load
    :vartype full_load_completed_tables: long
    :ivar full_load_loading_tables: Number of tables loading in full load
    :vartype full_load_loading_tables: long
    :ivar full_load_queued_tables: Number of tables queued in full load
    :vartype full_load_queued_tables: long
    :ivar full_load_errored_tables: Number of tables errored in full load
    :vartype full_load_errored_tables: long
    :ivar initialization_completed: Indicates if initial load (full load) has
     been completed
    :vartype initialization_completed: bool
    :ivar latency: CDC apply latency
    :vartype latency: long
    """

    _validation = {
        'id': {'readonly': True},
        'result_type': {'required': True},
        'database_name': {'readonly': True},
        'started_on': {'readonly': True},
        'ended_on': {'readonly': True},
        'migration_state': {'readonly': True},
        'incoming_changes': {'readonly': True},
        'applied_changes': {'readonly': True},
        'cdc_insert_counter': {'readonly': True},
        'cdc_delete_counter': {'readonly': True},
        'cdc_update_counter': {'readonly': True},
        'full_load_completed_tables': {'readonly': True},
        'full_load_loading_tables': {'readonly': True},
        'full_load_queued_tables': {'readonly': True},
        'full_load_errored_tables': {'readonly': True},
        'initialization_completed': {'readonly': True},
        'latency': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
        'database_name': {'key': 'databaseName', 'type': 'str'},
        'started_on': {'key': 'startedOn', 'type': 'iso-8601'},
        'ended_on': {'key': 'endedOn', 'type': 'iso-8601'},
        'migration_state': {'key': 'migrationState', 'type': 'str'},
        'incoming_changes': {'key': 'incomingChanges', 'type': 'long'},
        'applied_changes': {'key': 'appliedChanges', 'type': 'long'},
        'cdc_insert_counter': {'key': 'cdcInsertCounter', 'type': 'long'},
        'cdc_delete_counter': {'key': 'cdcDeleteCounter', 'type': 'long'},
        'cdc_update_counter': {'key': 'cdcUpdateCounter', 'type': 'long'},
        'full_load_completed_tables': {'key': 'fullLoadCompletedTables', 'type': 'long'},
        'full_load_loading_tables': {'key': 'fullLoadLoadingTables', 'type': 'long'},
        'full_load_queued_tables': {'key': 'fullLoadQueuedTables', 'type': 'long'},
        'full_load_errored_tables': {'key': 'fullLoadErroredTables', 'type': 'long'},
        'initialization_completed': {'key': 'initializationCompleted', 'type': 'bool'},
        'latency': {'key': 'latency', 'type': 'long'},
    }

    def __init__(self, **kwargs) -> None:
        super(MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutputDatabaseLevel, self).__init__(**kwargs)
        self.database_name = None
        self.started_on = None
        self.ended_on = None
        self.migration_state = None
        self.incoming_changes = None
        self.applied_changes = None
        self.cdc_insert_counter = None
        self.cdc_delete_counter = None
        self.cdc_update_counter = None
        self.full_load_completed_tables = None
        self.full_load_loading_tables = None
        self.full_load_queued_tables = None
        self.full_load_errored_tables = None
        self.initialization_completed = None
        self.latency = None
        self.result_type = 'DatabaseLevelOutput'
