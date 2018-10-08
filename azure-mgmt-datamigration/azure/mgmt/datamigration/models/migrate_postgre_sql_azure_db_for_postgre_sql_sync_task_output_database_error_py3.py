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


class MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutputDatabaseError(MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutput):
    """MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutputDatabaseError.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Result identifier
    :vartype id: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    :param error_message: Error message
    :type error_message: str
    :param events: List of error events.
    :type events:
     list[~azure.mgmt.datamigration.models.SyncMigrationDatabaseErrorEvent]
    """

    _validation = {
        'id': {'readonly': True},
        'result_type': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
        'error_message': {'key': 'errorMessage', 'type': 'str'},
        'events': {'key': 'events', 'type': '[SyncMigrationDatabaseErrorEvent]'},
    }

    def __init__(self, *, error_message: str=None, events=None, **kwargs) -> None:
        super(MigratePostgreSqlAzureDbForPostgreSqlSyncTaskOutputDatabaseError, self).__init__(**kwargs)
        self.error_message = error_message
        self.events = events
        self.result_type = 'DatabaseLevelErrorOutput'
