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


class BuildFilter(Model):
    """Properties that are enabled for Odata querying.

    :param build_id: The unique identifier for the build.
    :type build_id: str
    :param build_type: The type of build. Possible values include:
     'AutoBuild', 'QuickBuild'
    :type build_type: str or
     ~azure.mgmt.containerregistry.v2017_10_01.models.BuildType
    :param status: The current status of the build. Possible values include:
     'Queued', 'Started', 'Running', 'Succeeded', 'Failed', 'Canceled',
     'AbandonedAsSystemError', 'Timeout'
    :type status: str or
     ~azure.mgmt.containerregistry.v2017_10_01.models.BuildStatus
    :param create_time: The create time for a build.
    :type create_time: datetime
    :param finish_time: The time the build finished.
    :type finish_time: datetime
    :param output_image_names: The list of all images that were generated from
     the build.
    :type output_image_names: list[str]
    :param is_archive_enabled: The value that indicates whether archiving is
     enabled or not.
    :type is_archive_enabled: bool
    :param build_task_name: The name of the build task that the build
     corresponds to.
    :type build_task_name: str
    """

    _attribute_map = {
        'build_id': {'key': 'buildId', 'type': 'str'},
        'build_type': {'key': 'buildType', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'create_time': {'key': 'createTime', 'type': 'iso-8601'},
        'finish_time': {'key': 'finishTime', 'type': 'iso-8601'},
        'output_image_names': {'key': 'outputImageNames', 'type': '[str]'},
        'is_archive_enabled': {'key': 'isArchiveEnabled', 'type': 'bool'},
        'build_task_name': {'key': 'buildTaskName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(BuildFilter, self).__init__(**kwargs)
        self.build_id = kwargs.get('build_id', None)
        self.build_type = kwargs.get('build_type', None)
        self.status = kwargs.get('status', None)
        self.create_time = kwargs.get('create_time', None)
        self.finish_time = kwargs.get('finish_time', None)
        self.output_image_names = kwargs.get('output_image_names', None)
        self.is_archive_enabled = kwargs.get('is_archive_enabled', None)
        self.build_task_name = kwargs.get('build_task_name', None)
