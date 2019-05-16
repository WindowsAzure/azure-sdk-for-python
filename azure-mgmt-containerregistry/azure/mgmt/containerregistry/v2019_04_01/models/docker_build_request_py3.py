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

from .run_request_py3 import RunRequest


class DockerBuildRequest(RunRequest):
    """The parameters for a docker quick build.

    All required parameters must be populated in order to send to Azure.

    :param is_archive_enabled: The value that indicates whether archiving is
     enabled for the run or not. Default value: False .
    :type is_archive_enabled: bool
    :param type: Required. Constant filled by server.
    :type type: str
    :param image_names: The fully qualified image names including the
     repository and tag.
    :type image_names: list[str]
    :param is_push_enabled: The value of this property indicates whether the
     image built should be pushed to the registry or not. Default value: True .
    :type is_push_enabled: bool
    :param no_cache: The value of this property indicates whether the image
     cache is enabled or not. Default value: False .
    :type no_cache: bool
    :param docker_file_path: Required. The Docker file path relative to the
     source location.
    :type docker_file_path: str
    :param target: The name of the target build stage for the docker build.
    :type target: str
    :param arguments: The collection of override arguments to be used when
     executing the run.
    :type arguments:
     list[~azure.mgmt.containerregistry.v2019_04_01.models.Argument]
    :param timeout: Run timeout in seconds. Default value: 3600 .
    :type timeout: int
    :param platform: Required. The platform properties against which the run
     has to happen.
    :type platform:
     ~azure.mgmt.containerregistry.v2019_04_01.models.PlatformProperties
    :param agent_configuration: The machine configuration of the run agent.
    :type agent_configuration:
     ~azure.mgmt.containerregistry.v2019_04_01.models.AgentProperties
    :param source_location: The URL(absolute or relative) of the source
     context. It can be an URL to a tar or git repository.
     If it is relative URL, the relative path should be obtained from calling
     listBuildSourceUploadUrl API.
    :type source_location: str
    :param credentials: The properties that describes a set of credentials
     that will be used when this run is invoked.
    :type credentials:
     ~azure.mgmt.containerregistry.v2019_04_01.models.Credentials
    """

    _validation = {
        'type': {'required': True},
        'docker_file_path': {'required': True},
        'timeout': {'maximum': 28800, 'minimum': 300},
        'platform': {'required': True},
    }

    _attribute_map = {
        'is_archive_enabled': {'key': 'isArchiveEnabled', 'type': 'bool'},
        'type': {'key': 'type', 'type': 'str'},
        'image_names': {'key': 'imageNames', 'type': '[str]'},
        'is_push_enabled': {'key': 'isPushEnabled', 'type': 'bool'},
        'no_cache': {'key': 'noCache', 'type': 'bool'},
        'docker_file_path': {'key': 'dockerFilePath', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'arguments': {'key': 'arguments', 'type': '[Argument]'},
        'timeout': {'key': 'timeout', 'type': 'int'},
        'platform': {'key': 'platform', 'type': 'PlatformProperties'},
        'agent_configuration': {'key': 'agentConfiguration', 'type': 'AgentProperties'},
        'source_location': {'key': 'sourceLocation', 'type': 'str'},
        'credentials': {'key': 'credentials', 'type': 'Credentials'},
    }

    def __init__(self, *, docker_file_path: str, platform, is_archive_enabled: bool=False, image_names=None, is_push_enabled: bool=True, no_cache: bool=False, target: str=None, arguments=None, timeout: int=3600, agent_configuration=None, source_location: str=None, credentials=None, **kwargs) -> None:
        super(DockerBuildRequest, self).__init__(is_archive_enabled=is_archive_enabled, **kwargs)
        self.image_names = image_names
        self.is_push_enabled = is_push_enabled
        self.no_cache = no_cache
        self.docker_file_path = docker_file_path
        self.target = target
        self.arguments = arguments
        self.timeout = timeout
        self.platform = platform
        self.agent_configuration = agent_configuration
        self.source_location = source_location
        self.credentials = credentials
        self.type = 'DockerBuildRequest'
