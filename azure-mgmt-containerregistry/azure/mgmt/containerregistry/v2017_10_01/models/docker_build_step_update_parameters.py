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

from .build_step_properties_update_parameters import BuildStepPropertiesUpdateParameters


class DockerBuildStepUpdateParameters(BuildStepPropertiesUpdateParameters):
    """The properties for updating a docker build step.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Constant filled by server.
    :type type: str
    :param branch: The repository branch name.
    :type branch: str
    :param image_names: The fully qualified image names including the
     repository and tag.
    :type image_names: list[str]
    :param is_push_enabled: The value of this property indicates whether the
     image built should be pushed to the registry or not. Default value: False
     .
    :type is_push_enabled: bool
    :param no_cache: The value of this property indicates whether the image
     cache is enabled or not. Default value: False .
    :type no_cache: bool
    :param docker_file_path: The Docker file path relative to the source
     control root.
    :type docker_file_path: str
    :param context_path: The relative context path for a docker build in the
     source.
    :type context_path: str
    :param build_arguments: The custom arguments for building this build step.
    :type build_arguments:
     list[~azure.mgmt.containerregistry.v2017_10_01.models.BuildArgument]
    :param base_image_trigger: The type of the auto trigger for base image
     dependency updates. Possible values include: 'All', 'Runtime', 'None'
    :type base_image_trigger: str or
     ~azure.mgmt.containerregistry.v2017_10_01.models.BaseImageTriggerType
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'branch': {'key': 'branch', 'type': 'str'},
        'image_names': {'key': 'imageNames', 'type': '[str]'},
        'is_push_enabled': {'key': 'isPushEnabled', 'type': 'bool'},
        'no_cache': {'key': 'noCache', 'type': 'bool'},
        'docker_file_path': {'key': 'dockerFilePath', 'type': 'str'},
        'context_path': {'key': 'contextPath', 'type': 'str'},
        'build_arguments': {'key': 'buildArguments', 'type': '[BuildArgument]'},
        'base_image_trigger': {'key': 'baseImageTrigger', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(DockerBuildStepUpdateParameters, self).__init__(**kwargs)
        self.branch = kwargs.get('branch', None)
        self.image_names = kwargs.get('image_names', None)
        self.is_push_enabled = kwargs.get('is_push_enabled', False)
        self.no_cache = kwargs.get('no_cache', False)
        self.docker_file_path = kwargs.get('docker_file_path', None)
        self.context_path = kwargs.get('context_path', None)
        self.build_arguments = kwargs.get('build_arguments', None)
        self.base_image_trigger = kwargs.get('base_image_trigger', None)
        self.type = 'Docker'
