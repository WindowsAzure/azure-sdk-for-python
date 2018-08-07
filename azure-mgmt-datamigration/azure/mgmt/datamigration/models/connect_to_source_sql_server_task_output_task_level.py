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


class ConnectToSourceSqlServerTaskOutputTaskLevel(ConnectToSourceSqlServerTaskOutput):
    """Task level output for the task that validates connection to SQL Server and
    also validates source server requirements.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Result identifier
    :vartype id: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    :ivar databases: Source databases as a map from database name to database
     id
    :vartype databases: dict[str, str]
    :ivar logins: Source logins as a map from login name to login id.
    :vartype logins: dict[str, str]
    :ivar agent_jobs: Source agent jobs as a map from agent job name to id.
    :vartype agent_jobs: dict[str, str]
    :ivar source_server_version: Source server version
    :vartype source_server_version: str
    :ivar source_server_brand_version: Source server brand version
    :vartype source_server_brand_version: str
    :ivar validation_errors: Validation errors
    :vartype validation_errors:
     list[~azure.mgmt.datamigration.models.ReportableException]
    """

    _validation = {
        'id': {'readonly': True},
        'result_type': {'required': True},
        'databases': {'readonly': True},
        'logins': {'readonly': True},
        'agent_jobs': {'readonly': True},
        'source_server_version': {'readonly': True},
        'source_server_brand_version': {'readonly': True},
        'validation_errors': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
        'databases': {'key': 'databases', 'type': '{str}'},
        'logins': {'key': 'logins', 'type': '{str}'},
        'agent_jobs': {'key': 'agentJobs', 'type': '{str}'},
        'source_server_version': {'key': 'sourceServerVersion', 'type': 'str'},
        'source_server_brand_version': {'key': 'sourceServerBrandVersion', 'type': 'str'},
        'validation_errors': {'key': 'validationErrors', 'type': '[ReportableException]'},
    }

    def __init__(self, **kwargs):
        super(ConnectToSourceSqlServerTaskOutputTaskLevel, self).__init__(**kwargs)
        self.databases = None
        self.logins = None
        self.agent_jobs = None
        self.source_server_version = None
        self.source_server_brand_version = None
        self.validation_errors = None
        self.result_type = 'TaskLevelOutput'
