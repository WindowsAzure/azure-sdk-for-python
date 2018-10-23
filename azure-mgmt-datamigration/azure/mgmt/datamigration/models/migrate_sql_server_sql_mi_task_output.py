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


class MigrateSqlServerSqlMITaskOutput(Model):
    """Output for task that migrates SQL Server databases to Azure SQL Database
    Managed Instance.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: MigrateSqlServerSqlMITaskOutputError,
    MigrateSqlServerSqlMITaskOutputLoginLevel,
    MigrateSqlServerSqlMITaskOutputAgentJobLevel,
    MigrateSqlServerSqlMITaskOutputDatabaseLevel,
    MigrateSqlServerSqlMITaskOutputMigrationLevel

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Result identifier
    :vartype id: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    """

    _validation = {
        'id': {'readonly': True},
        'result_type': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
    }

    _subtype_map = {
        'result_type': {'ErrorOutput': 'MigrateSqlServerSqlMITaskOutputError', 'LoginLevelOutput': 'MigrateSqlServerSqlMITaskOutputLoginLevel', 'AgentJobLevelOutput': 'MigrateSqlServerSqlMITaskOutputAgentJobLevel', 'DatabaseLevelOutput': 'MigrateSqlServerSqlMITaskOutputDatabaseLevel', 'MigrationLevelOutput': 'MigrateSqlServerSqlMITaskOutputMigrationLevel'}
    }

    def __init__(self, **kwargs):
        super(MigrateSqlServerSqlMITaskOutput, self).__init__(**kwargs)
        self.id = None
        self.result_type = None
