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


class Trigger(Model):
    """Azure data factory nested object which contains information about creating
    pipeline run.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: RerunTumblingWindowTrigger, TumblingWindowTrigger,
    MultiplePipelineTrigger

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param description: Trigger description.
    :type description: str
    :ivar runtime_state: Indicates if trigger is running or not. Updated when
     Start/Stop APIs are called on the Trigger. Possible values include:
     'Started', 'Stopped', 'Disabled'
    :vartype runtime_state: str or
     ~azure.mgmt.datafactory.models.TriggerRuntimeState
    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'runtime_state': {'readonly': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'description': {'key': 'description', 'type': 'str'},
        'runtime_state': {'key': 'runtimeState', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'RerunTumblingWindowTrigger': 'RerunTumblingWindowTrigger', 'TumblingWindowTrigger': 'TumblingWindowTrigger', 'MultiplePipelineTrigger': 'MultiplePipelineTrigger'}
    }

    def __init__(self, **kwargs):
        super(Trigger, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.description = kwargs.get('description', None)
        self.runtime_state = None
        self.type = None
