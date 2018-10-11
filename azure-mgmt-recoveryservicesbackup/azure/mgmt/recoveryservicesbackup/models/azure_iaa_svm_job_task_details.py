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


class AzureIaaSVMJobTaskDetails(Model):
    """Azure IaaS VM workload-specific job task details.

    :param task_id: The task display name.
    :type task_id: str
    :param start_time: The start time.
    :type start_time: datetime
    :param end_time: The end time.
    :type end_time: datetime
    :param instance_id: The instanceId.
    :type instance_id: str
    :param duration: Time elapsed for task.
    :type duration: timedelta
    :param status: The status.
    :type status: str
    :param progress_percentage: Progress of the task.
    :type progress_percentage: float
    :param task_execution_details: Details about execution of the task.
     eg: number of bytes transfered etc
    :type task_execution_details: str
    """

    _attribute_map = {
        'task_id': {'key': 'taskId', 'type': 'str'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'instance_id': {'key': 'instanceId', 'type': 'str'},
        'duration': {'key': 'duration', 'type': 'duration'},
        'status': {'key': 'status', 'type': 'str'},
        'progress_percentage': {'key': 'progressPercentage', 'type': 'float'},
        'task_execution_details': {'key': 'taskExecutionDetails', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AzureIaaSVMJobTaskDetails, self).__init__(**kwargs)
        self.task_id = kwargs.get('task_id', None)
        self.start_time = kwargs.get('start_time', None)
        self.end_time = kwargs.get('end_time', None)
        self.instance_id = kwargs.get('instance_id', None)
        self.duration = kwargs.get('duration', None)
        self.status = kwargs.get('status', None)
        self.progress_percentage = kwargs.get('progress_percentage', None)
        self.task_execution_details = kwargs.get('task_execution_details', None)
