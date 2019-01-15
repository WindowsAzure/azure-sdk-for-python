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

from .job_properties import JobProperties


class HiveJobProperties(JobProperties):
    """Hive job properties used when retrieving Hive jobs.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param runtime_version: The runtime version of the Data Lake Analytics
     engine to use for the specific type of job being run.
    :type runtime_version: str
    :param script: Required. The script to run. Please note that the maximum
     script size is 3 MB.
    :type script: str
    :param type: Required. Constant filled by server.
    :type type: str
    :ivar logs_location: The Hive logs location.
    :vartype logs_location: str
    :ivar output_location: The location of Hive job output files (both
     execution output and results).
    :vartype output_location: str
    :ivar statement_count: The number of statements that will be run based on
     the script.
    :vartype statement_count: int
    :ivar executed_statement_count: The number of statements that have been
     run based on the script.
    :vartype executed_statement_count: int
    """

    _validation = {
        'script': {'required': True},
        'type': {'required': True},
        'logs_location': {'readonly': True},
        'output_location': {'readonly': True},
        'statement_count': {'readonly': True},
        'executed_statement_count': {'readonly': True},
    }

    _attribute_map = {
        'runtime_version': {'key': 'runtimeVersion', 'type': 'str'},
        'script': {'key': 'script', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'logs_location': {'key': 'logsLocation', 'type': 'str'},
        'output_location': {'key': 'outputLocation', 'type': 'str'},
        'statement_count': {'key': 'statementCount', 'type': 'int'},
        'executed_statement_count': {'key': 'executedStatementCount', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(HiveJobProperties, self).__init__(**kwargs)
        self.logs_location = None
        self.output_location = None
        self.statement_count = None
        self.executed_statement_count = None
        self.type = 'Hive'
