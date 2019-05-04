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


class StepOperationInfo(Model):
    """Detailed information of a specific step run.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar deployment_name: The name of the ARM deployment initiated as part of
     the step.
    :vartype deployment_name: str
    :ivar correlation_id: Unique identifier to track the request for ARM-based
     resources.
    :vartype correlation_id: str
    :ivar start_time: Start time of the action in UTC.
    :vartype start_time: datetime
    :ivar end_time: End time of the action in UTC.
    :vartype end_time: datetime
    :ivar last_updated_time: Last time in UTC this operation was updated.
    :vartype last_updated_time: datetime
    :param error: The errors, if any, for the action.
    :type error: ~azure.mgmt.deploymentmanager.models.CloudErrorBody
    """

    _validation = {
        'deployment_name': {'readonly': True},
        'correlation_id': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
        'last_updated_time': {'readonly': True},
    }

    _attribute_map = {
        'deployment_name': {'key': 'deploymentName', 'type': 'str'},
        'correlation_id': {'key': 'correlationId', 'type': 'str'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'last_updated_time': {'key': 'lastUpdatedTime', 'type': 'iso-8601'},
        'error': {'key': 'error', 'type': 'CloudErrorBody'},
    }

    def __init__(self, **kwargs):
        super(StepOperationInfo, self).__init__(**kwargs)
        self.deployment_name = None
        self.correlation_id = None
        self.start_time = None
        self.end_time = None
        self.last_updated_time = None
        self.error = kwargs.get('error', None)
