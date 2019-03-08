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

from .run_request import RunRequest


class FileTaskRunRequest(RunRequest):
    """The request parameters for a scheduling run against a task file.

    All required parameters must be populated in order to send to Azure.

    :param is_archive_enabled: The value that indicates whether archiving is
     enabled for the run or not. Default value: False .
    :type is_archive_enabled: bool
    :param type: Required. Constant filled by server.
    :type type: str
    :param task_file_path: Required. The template/definition file path
     relative to the source.
    :type task_file_path: str
    :param values_file_path: The values/parameters file path relative to the
     source.
    :type values_file_path: str
    :param values: The collection of overridable values that can be passed
     when running a task.
    :type values:
     list[~azure.mgmt.containerregistry.v2018_09_01.models.SetValue]
    :param timeout: Run timeout in seconds. Default value: 3600 .
    :type timeout: int
    :param platform: Required. The platform properties against which the run
     has to happen.
    :type platform:
     ~azure.mgmt.containerregistry.v2018_09_01.models.PlatformProperties
    :param agent_configuration: The machine configuration of the run agent.
    :type agent_configuration:
     ~azure.mgmt.containerregistry.v2018_09_01.models.AgentProperties
    :param source_location: The URL(absolute or relative) of the source
     context. It can be an URL to a tar or git repository.
     If it is relative URL, the relative path should be obtained from calling
     listBuildSourceUploadUrl API.
    :type source_location: str
    :param credentials: The properties that describes a set of credentials
     that will be used when this run is invoked.
    :type credentials:
     ~azure.mgmt.containerregistry.v2018_09_01.models.Credentials
    """

    _validation = {
        'type': {'required': True},
        'task_file_path': {'required': True},
        'timeout': {'maximum': 28800, 'minimum': 300},
        'platform': {'required': True},
    }

    _attribute_map = {
        'is_archive_enabled': {'key': 'isArchiveEnabled', 'type': 'bool'},
        'type': {'key': 'type', 'type': 'str'},
        'task_file_path': {'key': 'taskFilePath', 'type': 'str'},
        'values_file_path': {'key': 'valuesFilePath', 'type': 'str'},
        'values': {'key': 'values', 'type': '[SetValue]'},
        'timeout': {'key': 'timeout', 'type': 'int'},
        'platform': {'key': 'platform', 'type': 'PlatformProperties'},
        'agent_configuration': {'key': 'agentConfiguration', 'type': 'AgentProperties'},
        'source_location': {'key': 'sourceLocation', 'type': 'str'},
        'credentials': {'key': 'credentials', 'type': 'Credentials'},
    }

    def __init__(self, **kwargs):
        super(FileTaskRunRequest, self).__init__(**kwargs)
        self.task_file_path = kwargs.get('task_file_path', None)
        self.values_file_path = kwargs.get('values_file_path', None)
        self.values = kwargs.get('values', None)
        self.timeout = kwargs.get('timeout', 3600)
        self.platform = kwargs.get('platform', None)
        self.agent_configuration = kwargs.get('agent_configuration', None)
        self.source_location = kwargs.get('source_location', None)
        self.credentials = kwargs.get('credentials', None)
        self.type = 'FileTaskRunRequest'
