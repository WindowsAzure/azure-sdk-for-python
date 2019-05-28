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

from .task_step_properties_py3 import TaskStepProperties


class DockerBuildStep(TaskStepProperties):
    """The Docker build step.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar base_image_dependencies: List of base image dependencies for a step.
    :vartype base_image_dependencies:
     list[~azure.mgmt.containerregistry.v2019_04_01.models.BaseImageDependency]
    :param context_path: The URL(absolute or relative) of the source context
     for the task step.
    :type context_path: str
    :param context_access_token: The token (git PAT or SAS token of storage
     account blob) associated with the context for a step.
    :type context_access_token: str
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
     source context.
    :type docker_file_path: str
    :param target: The name of the target build stage for the docker build.
    :type target: str
    :param arguments: The collection of override arguments to be used when
     executing this build step.
    :type arguments:
     list[~azure.mgmt.containerregistry.v2019_04_01.models.Argument]
    """

    _validation = {
        'base_image_dependencies': {'readonly': True},
        'type': {'required': True},
        'docker_file_path': {'required': True},
    }

    _attribute_map = {
        'base_image_dependencies': {'key': 'baseImageDependencies', 'type': '[BaseImageDependency]'},
        'context_path': {'key': 'contextPath', 'type': 'str'},
        'context_access_token': {'key': 'contextAccessToken', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'image_names': {'key': 'imageNames', 'type': '[str]'},
        'is_push_enabled': {'key': 'isPushEnabled', 'type': 'bool'},
        'no_cache': {'key': 'noCache', 'type': 'bool'},
        'docker_file_path': {'key': 'dockerFilePath', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'arguments': {'key': 'arguments', 'type': '[Argument]'},
    }

    def __init__(self, *, docker_file_path: str, context_path: str=None, context_access_token: str=None, image_names=None, is_push_enabled: bool=True, no_cache: bool=False, target: str=None, arguments=None, **kwargs) -> None:
        super(DockerBuildStep, self).__init__(context_path=context_path, context_access_token=context_access_token, **kwargs)
        self.image_names = image_names
        self.is_push_enabled = is_push_enabled
        self.no_cache = no_cache
        self.docker_file_path = docker_file_path
        self.target = target
        self.arguments = arguments
        self.type = 'Docker'
