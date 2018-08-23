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


class RecurrenceSchedule(Model):
    """The recurrence schedule.

    :param minutes: The minutes.
    :type minutes: list[int]
    :param hours: The hours.
    :type hours: list[int]
    :param week_days: The days of the week.
    :type week_days: list[str or ~azure.mgmt.logic.models.DaysOfWeek]
    :param month_days: The month days.
    :type month_days: list[int]
    :param monthly_occurrences: The monthly occurrences.
    :type monthly_occurrences:
     list[~azure.mgmt.logic.models.RecurrenceScheduleOccurrence]
    """

    _attribute_map = {
        'minutes': {'key': 'minutes', 'type': '[int]'},
        'hours': {'key': 'hours', 'type': '[int]'},
        'week_days': {'key': 'weekDays', 'type': '[str]'},
        'month_days': {'key': 'monthDays', 'type': '[int]'},
        'monthly_occurrences': {'key': 'monthlyOccurrences', 'type': '[RecurrenceScheduleOccurrence]'},
    }

    def __init__(self, *, minutes=None, hours=None, week_days=None, month_days=None, monthly_occurrences=None, **kwargs) -> None:
        super(RecurrenceSchedule, self).__init__(**kwargs)
        self.minutes = minutes
        self.hours = hours
        self.week_days = week_days
        self.month_days = month_days
        self.monthly_occurrences = monthly_occurrences
