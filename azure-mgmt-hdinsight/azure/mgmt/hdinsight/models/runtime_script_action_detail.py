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

from .runtime_script_action import RuntimeScriptAction


class RuntimeScriptActionDetail(RuntimeScriptAction):
    """The execution details of a script action.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the script action.
    :type name: str
    :param uri: Required. The URI to the script.
    :type uri: str
    :param parameters: The parameters for the script
    :type parameters: str
    :param roles: Required. The list of roles where script will be executed.
    :type roles: list[str]
    :ivar application_name: The application name of the script action, if any.
    :vartype application_name: str
    :ivar script_execution_id: The execution id of the script action.
    :vartype script_execution_id: long
    :ivar start_time: The start time of script action execution.
    :vartype start_time: str
    :ivar end_time: The end time of script action execution.
    :vartype end_time: str
    :ivar status: The current execution status of the script action.
    :vartype status: str
    :ivar operation: The reason why the script action was executed.
    :vartype operation: str
    :ivar execution_summary: The summary of script action execution result.
    :vartype execution_summary:
     list[~azure.mgmt.hdinsight.models.ScriptActionExecutionSummary]
    :ivar debug_information: The script action execution debug information.
    :vartype debug_information: str
    """

    _validation = {
        'name': {'required': True},
        'uri': {'required': True},
        'roles': {'required': True},
        'application_name': {'readonly': True},
        'script_execution_id': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
        'status': {'readonly': True},
        'operation': {'readonly': True},
        'execution_summary': {'readonly': True},
        'debug_information': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'uri': {'key': 'uri', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': 'str'},
        'roles': {'key': 'roles', 'type': '[str]'},
        'application_name': {'key': 'applicationName', 'type': 'str'},
        'script_execution_id': {'key': 'scriptExecutionId', 'type': 'long'},
        'start_time': {'key': 'startTime', 'type': 'str'},
        'end_time': {'key': 'endTime', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'execution_summary': {'key': 'executionSummary', 'type': '[ScriptActionExecutionSummary]'},
        'debug_information': {'key': 'debugInformation', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RuntimeScriptActionDetail, self).__init__(**kwargs)
        self.script_execution_id = None
        self.start_time = None
        self.end_time = None
        self.status = None
        self.operation = None
        self.execution_summary = None
        self.debug_information = None
