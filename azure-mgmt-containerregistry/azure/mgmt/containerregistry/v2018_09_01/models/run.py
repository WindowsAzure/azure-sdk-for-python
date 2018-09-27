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

from .proxy_resource import ProxyResource


class Run(ProxyResource):
    """Run resource properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param run_id: The unique identifier for the run.
    :type run_id: str
    :param status: The current status of the run. Possible values include:
     'Queued', 'Started', 'Running', 'Succeeded', 'Failed', 'Canceled',
     'Error', 'Timeout'
    :type status: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.RunStatus
    :param last_updated_time: The last updated time for the run.
    :type last_updated_time: datetime
    :param run_type: The type of run. Possible values include: 'QuickBuild',
     'AutoBuild'
    :type run_type: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.RunType
    :param create_time: The time the run was scheduled.
    :type create_time: datetime
    :param start_time: The time the run started.
    :type start_time: datetime
    :param finish_time: The time the run finished.
    :type finish_time: datetime
    :param output_images: The list of all images that were generated from the
     run. This is applicable if the run is of type Build.
    :type output_images:
     list[~azure.mgmt.containerregistry.v2018_09_01.models.ImageDescriptor]
    :param task: The task against which run was scheduled.
    :type task: str
    :param image_update_trigger: The image update trigger that caused the run.
     This is applicable if the task is of build type.
    :type image_update_trigger:
     ~azure.mgmt.containerregistry.v2018_09_01.models.ImageUpdateTrigger
    :param source_trigger: The source trigger that caused the run.
    :type source_trigger:
     ~azure.mgmt.containerregistry.v2018_09_01.models.SourceTriggerDescriptor
    :param is_archive_enabled: The value that indicates whether archiving is
     enabled or not. Default value: False .
    :type is_archive_enabled: bool
    :param platform: The platform properties against which the run will
     happen.
    :type platform:
     ~azure.mgmt.containerregistry.v2018_09_01.models.PlatformProperties
    :param agent_configuration: The machine configuration of the run agent.
    :type agent_configuration:
     ~azure.mgmt.containerregistry.v2018_09_01.models.AgentProperties
    :param provisioning_state: The provisioning state of a run. Possible
     values include: 'Creating', 'Updating', 'Deleting', 'Succeeded', 'Failed',
     'Canceled'
    :type provisioning_state: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.ProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'run_id': {'key': 'properties.runId', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'last_updated_time': {'key': 'properties.lastUpdatedTime', 'type': 'iso-8601'},
        'run_type': {'key': 'properties.runType', 'type': 'str'},
        'create_time': {'key': 'properties.createTime', 'type': 'iso-8601'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'finish_time': {'key': 'properties.finishTime', 'type': 'iso-8601'},
        'output_images': {'key': 'properties.outputImages', 'type': '[ImageDescriptor]'},
        'task': {'key': 'properties.task', 'type': 'str'},
        'image_update_trigger': {'key': 'properties.imageUpdateTrigger', 'type': 'ImageUpdateTrigger'},
        'source_trigger': {'key': 'properties.sourceTrigger', 'type': 'SourceTriggerDescriptor'},
        'is_archive_enabled': {'key': 'properties.isArchiveEnabled', 'type': 'bool'},
        'platform': {'key': 'properties.platform', 'type': 'PlatformProperties'},
        'agent_configuration': {'key': 'properties.agentConfiguration', 'type': 'AgentProperties'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Run, self).__init__(**kwargs)
        self.run_id = kwargs.get('run_id', None)
        self.status = kwargs.get('status', None)
        self.last_updated_time = kwargs.get('last_updated_time', None)
        self.run_type = kwargs.get('run_type', None)
        self.create_time = kwargs.get('create_time', None)
        self.start_time = kwargs.get('start_time', None)
        self.finish_time = kwargs.get('finish_time', None)
        self.output_images = kwargs.get('output_images', None)
        self.task = kwargs.get('task', None)
        self.image_update_trigger = kwargs.get('image_update_trigger', None)
        self.source_trigger = kwargs.get('source_trigger', None)
        self.is_archive_enabled = kwargs.get('is_archive_enabled', False)
        self.platform = kwargs.get('platform', None)
        self.agent_configuration = kwargs.get('agent_configuration', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
