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


class MigrateSqlServerSqlMITaskOutputLoginLevel(MigrateSqlServerSqlMITaskOutput):
    """MigrateSqlServerSqlMITaskOutputLoginLevel.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Result identifier
    :vartype id: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    :ivar login_name: Login name.
    :vartype login_name: str
    :ivar state: Current state of login. Possible values include: 'None',
     'InProgress', 'Failed', 'Warning', 'Completed', 'Skipped', 'Stopped'
    :vartype state: str or ~azure.mgmt.datamigration.models.MigrationState
    :ivar stage: Current stage of login. Possible values include: 'None',
     'Initialize', 'LoginMigration', 'EstablishUserMapping',
     'AssignRoleMembership', 'AssignRoleOwnership',
     'EstablishServerPermissions', 'EstablishObjectPermissions', 'Completed'
    :vartype stage: str or
     ~azure.mgmt.datamigration.models.LoginMigrationStage
    :ivar started_on: Login migration start time
    :vartype started_on: datetime
    :ivar ended_on: Login migration end time
    :vartype ended_on: datetime
    :ivar message: Login migration progress message
    :vartype message: str
    :ivar exceptions_and_warnings: Login migration errors and warnings per
     login
    :vartype exceptions_and_warnings:
     list[~azure.mgmt.datamigration.models.ReportableException]
    """

    _validation = {
        'id': {'readonly': True},
        'result_type': {'required': True},
        'login_name': {'readonly': True},
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
        'login_name': {'key': 'loginName', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'stage': {'key': 'stage', 'type': 'LoginMigrationStage'},
        'started_on': {'key': 'startedOn', 'type': 'iso-8601'},
        'ended_on': {'key': 'endedOn', 'type': 'iso-8601'},
        'message': {'key': 'message', 'type': 'str'},
        'exceptions_and_warnings': {'key': 'exceptionsAndWarnings', 'type': '[ReportableException]'},
    }

    def __init__(self, **kwargs) -> None:
        super(MigrateSqlServerSqlMITaskOutputLoginLevel, self).__init__(**kwargs)
        self.login_name = None
        self.state = None
        self.stage = None
        self.started_on = None
        self.ended_on = None
        self.message = None
        self.exceptions_and_warnings = None
        self.result_type = 'LoginLevelOutput'
