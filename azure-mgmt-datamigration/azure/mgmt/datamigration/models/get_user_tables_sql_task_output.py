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

from .task_output import TaskOutput


class GetUserTablesSqlTaskOutput(TaskOutput):
    """Output of the task that collects user tables for the given list of
    databases.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Result identifier
    :vartype id: str
    :ivar databases_to_tables: Mapping from database name to list of tables
    :vartype databases_to_tables: dict[str,
     list[~azure.mgmt.datamigration.models.DatabaseTable]]
    :ivar validation_errors: Validation errors
    :vartype validation_errors:
     list[~azure.mgmt.datamigration.models.ReportableException]
    """

    _validation = {
        'id': {'readonly': True},
        'databases_to_tables': {'readonly': True},
        'validation_errors': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'databases_to_tables': {'key': 'databasesToTables', 'type': '{[DatabaseTable]}'},
        'validation_errors': {'key': 'validationErrors', 'type': '[ReportableException]'},
    }

    def __init__(self):
        super(GetUserTablesSqlTaskOutput, self).__init__()
        self.databases_to_tables = None
        self.validation_errors = None
