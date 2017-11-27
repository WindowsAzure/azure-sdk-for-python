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


class ScheduleTriggerRecurrence(Model):
    """The workflow trigger recurrence.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param frequency: The frequency. Possible values include: 'NotSpecified',
     'Minute', 'Hour', 'Day', 'Week', 'Month', 'Year'
    :type frequency: str or ~azure.mgmt.datafactory.models.RecurrenceFrequency
    :param interval: The interval.
    :type interval: int
    :param start_time: The start time.
    :type start_time: datetime
    :param end_time: The end time.
    :type end_time: datetime
    :param time_zone: The time zone.
    :type time_zone: str
    :param schedule: The recurrence schedule.
    :type schedule: ~azure.mgmt.datafactory.models.RecurrenceSchedule
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'frequency': {'key': 'frequency', 'type': 'str'},
        'interval': {'key': 'interval', 'type': 'int'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'time_zone': {'key': 'timeZone', 'type': 'str'},
        'schedule': {'key': 'schedule', 'type': 'RecurrenceSchedule'},
    }

    def __init__(self, additional_properties=None, frequency=None, interval=None, start_time=None, end_time=None, time_zone=None, schedule=None):
        self.additional_properties = additional_properties
        self.frequency = frequency
        self.interval = interval
        self.start_time = start_time
        self.end_time = end_time
        self.time_zone = time_zone
        self.schedule = schedule
