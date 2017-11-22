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

from .multiple_pipeline_trigger import MultiplePipelineTrigger


class ScheduleTrigger(MultiplePipelineTrigger):
    """Trigger that creates pipeline runs periodically, on schedule.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param description: Trigger description.
    :type description: str
    :ivar runtime_state: Indicates if trigger is running or not. Updated when
     Start/Stop APIs are called on the Trigger. Possible values include:
     'Started', 'Stopped', 'Disabled'
    :vartype runtime_state: str or
     ~azure.mgmt.datafactory.models.TriggerRuntimeState
    :param type: Constant filled by server.
    :type type: str
    :param pipelines: Pipelines that need to be started.
    :type pipelines:
     list[~azure.mgmt.datafactory.models.TriggerPipelineReference]
    :param recurrence: Recurrence schedule configuration.
    :type recurrence: ~azure.mgmt.datafactory.models.ScheduleTriggerRecurrence
    """

    _validation = {
        'runtime_state': {'readonly': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'runtime_state': {'key': 'runtimeState', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'pipelines': {'key': 'pipelines', 'type': '[TriggerPipelineReference]'},
        'recurrence': {'key': 'typeProperties.recurrence', 'type': 'ScheduleTriggerRecurrence'},
    }

    def __init__(self, description=None, pipelines=None, recurrence=None):
        super(ScheduleTrigger, self).__init__(description=description, pipelines=pipelines)
        self.recurrence = recurrence
        self.type = 'ScheduleTrigger'
