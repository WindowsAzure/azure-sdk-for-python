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

from .proxy_resource_py3 import ProxyResource


class Job(ProxyResource):
    """A Job resource type. The progress and state can be obtained by polling a
    Job or subscribing to events using EventGrid.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :ivar created: The UTC date and time when the Job was created, in
     'YYYY-MM-DDThh:mm:ssZ' format.
    :vartype created: datetime
    :ivar state: The current state of the job. Possible values include:
     'Canceled', 'Canceling', 'Error', 'Finished', 'Processing', 'Queued',
     'Scheduled'
    :vartype state: str or ~azure.mgmt.media.models.JobState
    :param description: Optional customer supplied description of the Job.
    :type description: str
    :param input: Required. The inputs for the Job.
    :type input: ~azure.mgmt.media.models.JobInput
    :ivar last_modified: The UTC date and time when the Job was last updated,
     in 'YYYY-MM-DDThh:mm:ssZ' format.
    :vartype last_modified: datetime
    :param outputs: Required. The outputs for the Job.
    :type outputs: list[~azure.mgmt.media.models.JobOutput]
    :param priority: Priority with which the job should be processed. Higher
     priority jobs are processed before lower priority jobs. If not set, the
     default is normal. Possible values include: 'Low', 'Normal', 'High'
    :type priority: str or ~azure.mgmt.media.models.Priority
    :param correlation_data: Customer provided correlation data that will be
     returned in Job and JobOutput state events.
    :type correlation_data: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created': {'readonly': True},
        'state': {'readonly': True},
        'input': {'required': True},
        'last_modified': {'readonly': True},
        'outputs': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'created': {'key': 'properties.created', 'type': 'iso-8601'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'input': {'key': 'properties.input', 'type': 'JobInput'},
        'last_modified': {'key': 'properties.lastModified', 'type': 'iso-8601'},
        'outputs': {'key': 'properties.outputs', 'type': '[JobOutput]'},
        'priority': {'key': 'properties.priority', 'type': 'str'},
        'correlation_data': {'key': 'properties.correlationData', 'type': '{str}'},
    }

    def __init__(self, *, input, outputs, description: str=None, priority=None, correlation_data=None, **kwargs) -> None:
        super(Job, self).__init__(**kwargs)
        self.created = None
        self.state = None
        self.description = description
        self.input = input
        self.last_modified = None
        self.outputs = outputs
        self.priority = priority
        self.correlation_data = correlation_data
