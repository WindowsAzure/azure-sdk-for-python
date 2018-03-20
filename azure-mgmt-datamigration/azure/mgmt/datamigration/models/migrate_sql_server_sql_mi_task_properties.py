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

from .project_task_properties import ProjectTaskProperties


class MigrateSqlServerSqlMITaskProperties(ProjectTaskProperties):
    """Properties for task that migrates SQL Server databases to Azure SQL
    Database Managed Instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar errors: Array of errors. This is ignored if submitted.
    :vartype errors: list[~azure.mgmt.datamigration.models.ODataError]
    :ivar state: The state of the task. This is ignored if submitted. Possible
     values include: 'Unknown', 'Queued', 'Running', 'Canceled', 'Succeeded',
     'Failed', 'FailedInputValidation', 'Faulted'
    :vartype state: str or ~azure.mgmt.datamigration.models.TaskState
    :param task_type: Required. Constant filled by server.
    :type task_type: str
    :param input: Task input
    :type input:
     ~azure.mgmt.datamigration.models.MigrateSqlServerSqlMITaskInput
    :ivar output: Task output. This is ignored if submitted.
    :vartype output:
     list[~azure.mgmt.datamigration.models.MigrateSqlServerSqlMITaskOutput]
    """

    _validation = {
        'errors': {'readonly': True},
        'state': {'readonly': True},
        'task_type': {'required': True},
        'output': {'readonly': True},
    }

    _attribute_map = {
        'errors': {'key': 'errors', 'type': '[ODataError]'},
        'state': {'key': 'state', 'type': 'str'},
        'task_type': {'key': 'taskType', 'type': 'str'},
        'input': {'key': 'input', 'type': 'MigrateSqlServerSqlMITaskInput'},
        'output': {'key': 'output', 'type': '[MigrateSqlServerSqlMITaskOutput]'},
    }

    def __init__(self, **kwargs):
        super(MigrateSqlServerSqlMITaskProperties, self).__init__(**kwargs)
        self.input = kwargs.get('input', None)
        self.output = None
        self.task_type = 'Migrate.SqlServer.AzureSqlDbMI'
