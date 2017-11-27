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


class ActivityRun(Model):
    """Information about an activity run in a pipeline.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :ivar pipeline_name: The name of the pipeline.
    :vartype pipeline_name: str
    :ivar pipeline_run_id: The id of the pipeline run.
    :vartype pipeline_run_id: str
    :ivar activity_name: The name of the activity.
    :vartype activity_name: str
    :ivar activity_type: The type of the activity.
    :vartype activity_type: str
    :ivar activity_run_id: The id of the activity run.
    :vartype activity_run_id: str
    :ivar linked_service_name: The name of the compute linked service.
    :vartype linked_service_name: str
    :ivar status: The status of the activity run.
    :vartype status: str
    :ivar activity_run_start: The start time of the activity run in 'ISO 8601'
     format.
    :vartype activity_run_start: datetime
    :ivar activity_run_end: The end time of the activity run in 'ISO 8601'
     format.
    :vartype activity_run_end: datetime
    :ivar duration_in_ms: The duration of the activity run.
    :vartype duration_in_ms: int
    :ivar input: The input for the activity.
    :vartype input: object
    :ivar output: The output for the activity.
    :vartype output: object
    :ivar error: The error if any from the activity run.
    :vartype error: object
    """

    _validation = {
        'pipeline_name': {'readonly': True},
        'pipeline_run_id': {'readonly': True},
        'activity_name': {'readonly': True},
        'activity_type': {'readonly': True},
        'activity_run_id': {'readonly': True},
        'linked_service_name': {'readonly': True},
        'status': {'readonly': True},
        'activity_run_start': {'readonly': True},
        'activity_run_end': {'readonly': True},
        'duration_in_ms': {'readonly': True},
        'input': {'readonly': True},
        'output': {'readonly': True},
        'error': {'readonly': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'pipeline_name': {'key': 'pipelineName', 'type': 'str'},
        'pipeline_run_id': {'key': 'pipelineRunId', 'type': 'str'},
        'activity_name': {'key': 'activityName', 'type': 'str'},
        'activity_type': {'key': 'activityType', 'type': 'str'},
        'activity_run_id': {'key': 'activityRunId', 'type': 'str'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'activity_run_start': {'key': 'activityRunStart', 'type': 'iso-8601'},
        'activity_run_end': {'key': 'activityRunEnd', 'type': 'iso-8601'},
        'duration_in_ms': {'key': 'durationInMs', 'type': 'int'},
        'input': {'key': 'input', 'type': 'object'},
        'output': {'key': 'output', 'type': 'object'},
        'error': {'key': 'error', 'type': 'object'},
    }

    def __init__(self, additional_properties=None):
        self.additional_properties = additional_properties
        self.pipeline_name = None
        self.pipeline_run_id = None
        self.activity_name = None
        self.activity_type = None
        self.activity_run_id = None
        self.linked_service_name = None
        self.status = None
        self.activity_run_start = None
        self.activity_run_end = None
        self.duration_in_ms = None
        self.input = None
        self.output = None
        self.error = None
