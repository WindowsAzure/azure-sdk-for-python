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


class JobSchedule(Model):
    """Scheduling properties of a job.

    :param start_time: Schedule start time. Default value:
     "0001-01-01T00:00:00Z" .
    :type start_time: datetime
    :param end_time: Schedule end time. Default value: "9999-12-31T11:59:59Z"
     .
    :type end_time: datetime
    :param type: Schedule interval type. Possible values include: 'Once',
     'Recurring'. Default value: "Once" .
    :type type: str or ~azure.mgmt.sql.models.JobScheduleType
    :param enabled: Whether or not the schedule is enabled.
    :type enabled: bool
    :param interval: Value of the schedule's recurring interval, if the
     scheduletype is recurring. ISO8601 duration format.
    :type interval: str
    """

    _attribute_map = {
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'type': {'key': 'type', 'type': 'JobScheduleType'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'interval': {'key': 'interval', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(JobSchedule, self).__init__(**kwargs)
        self.start_time = kwargs.get('start_time', "0001-01-01T00:00:00Z")
        self.end_time = kwargs.get('end_time', "9999-12-31T11:59:59Z")
        self.type = kwargs.get('type', "Once")
        self.enabled = kwargs.get('enabled', None)
        self.interval = kwargs.get('interval', None)
