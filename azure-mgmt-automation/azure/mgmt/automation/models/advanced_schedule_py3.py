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


class AdvancedSchedule(Model):
    """The properties of the create Advanced Schedule.

    :param week_days: Days of the week that the job should execute on.
    :type week_days: list[str]
    :param month_days: Days of the month that the job should execute on. Must
     be between 1 and 31.
    :type month_days: list[int]
    :param monthly_occurrences: Occurrences of days within a month.
    :type monthly_occurrences:
     list[~azure.mgmt.automation.models.AdvancedScheduleMonthlyOccurrence]
    """

    _attribute_map = {
        'week_days': {'key': 'weekDays', 'type': '[str]'},
        'month_days': {'key': 'monthDays', 'type': '[int]'},
        'monthly_occurrences': {'key': 'monthlyOccurrences', 'type': '[AdvancedScheduleMonthlyOccurrence]'},
    }

    def __init__(self, *, week_days=None, month_days=None, monthly_occurrences=None, **kwargs) -> None:
        super(AdvancedSchedule, self).__init__(**kwargs)
        self.week_days = week_days
        self.month_days = month_days
        self.monthly_occurrences = monthly_occurrences
