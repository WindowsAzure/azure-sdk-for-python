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

from .resource import Resource


class Task(Resource):
    """The task that has the ARM resource and task properties.
    The task will have all information to schedule a run against it.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: Required. The location of the resource. This cannot be
     changed after the resource is created.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :ivar provisioning_state: The provisioning state of the task. Possible
     values include: 'Creating', 'Updating', 'Deleting', 'Succeeded', 'Failed',
     'Canceled'
    :vartype provisioning_state: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.ProvisioningState
    :ivar creation_date: The creation date of task.
    :vartype creation_date: datetime
    :param status: The current status of task. Possible values include:
     'Disabled', 'Enabled'
    :type status: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.TaskStatus
    :param platform: Required. The platform properties against which the run
     has to happen.
    :type platform:
     ~azure.mgmt.containerregistry.v2018_09_01.models.PlatformProperties
    :param agent_configuration: The machine configuration of the run agent.
    :type agent_configuration:
     ~azure.mgmt.containerregistry.v2018_09_01.models.AgentProperties
    :param timeout: Run timeout in seconds. Default value: 3600 .
    :type timeout: int
    :param step: Required. The properties of a task step.
    :type step:
     ~azure.mgmt.containerregistry.v2018_09_01.models.TaskStepProperties
    :param trigger: The properties that describe all triggers for the task.
    :type trigger:
     ~azure.mgmt.containerregistry.v2018_09_01.models.TriggerProperties
    :param credentials: The properties that describes a set of credentials
     that will be used when this run is invoked.
    :type credentials:
     ~azure.mgmt.containerregistry.v2018_09_01.models.Credentials
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'creation_date': {'readonly': True},
        'platform': {'required': True},
        'timeout': {'maximum': 28800, 'minimum': 300},
        'step': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'creation_date': {'key': 'properties.creationDate', 'type': 'iso-8601'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'platform': {'key': 'properties.platform', 'type': 'PlatformProperties'},
        'agent_configuration': {'key': 'properties.agentConfiguration', 'type': 'AgentProperties'},
        'timeout': {'key': 'properties.timeout', 'type': 'int'},
        'step': {'key': 'properties.step', 'type': 'TaskStepProperties'},
        'trigger': {'key': 'properties.trigger', 'type': 'TriggerProperties'},
        'credentials': {'key': 'properties.credentials', 'type': 'Credentials'},
    }

    def __init__(self, **kwargs):
        super(Task, self).__init__(**kwargs)
        self.provisioning_state = None
        self.creation_date = None
        self.status = kwargs.get('status', None)
        self.platform = kwargs.get('platform', None)
        self.agent_configuration = kwargs.get('agent_configuration', None)
        self.timeout = kwargs.get('timeout', 3600)
        self.step = kwargs.get('step', None)
        self.trigger = kwargs.get('trigger', None)
        self.credentials = kwargs.get('credentials', None)
