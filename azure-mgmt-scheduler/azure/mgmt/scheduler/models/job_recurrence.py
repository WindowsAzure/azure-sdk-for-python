# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class JobRecurrence(Model):
    """JobRecurrence

    :param frequency: Gets or sets the frequency of recurrence (second,
     minute, hour, day, week, month). Possible values include: 'Minute',
     'Hour', 'Day', 'Week', 'Month'
    :type frequency: str or :class:`RecurrenceFrequency
     <schedulermanagementclient.models.RecurrenceFrequency>`
    :param interval: Gets or sets the interval between retries.
    :type interval: int
    :param count: Gets or sets the maximum number of times that the job
     should run.
    :type count: int
    :param end_time: Gets or sets the time at which the job will complete.
    :type end_time: datetime
    :param schedule:
    :type schedule: :class:`JobRecurrenceSchedule
     <azure.mgmt.scheduler.models.JobRecurrenceSchedule>`
    """ 

    _attribute_map = {
        'frequency': {'key': 'frequency', 'type': 'RecurrenceFrequency'},
        'interval': {'key': 'interval', 'type': 'int'},
        'count': {'key': 'count', 'type': 'int'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'schedule': {'key': 'schedule', 'type': 'JobRecurrenceSchedule'},
    }

    def __init__(self, frequency=None, interval=None, count=None, end_time=None, schedule=None):
        self.frequency = frequency
        self.interval = interval
        self.count = count
        self.end_time = end_time
        self.schedule = schedule
