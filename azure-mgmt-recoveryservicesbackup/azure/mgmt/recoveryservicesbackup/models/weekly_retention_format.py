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


class WeeklyRetentionFormat(Model):
    """Weekly retention format.

    :param days_of_the_week: List of days of the week.
    :type days_of_the_week: list[str or
     ~azure.mgmt.recoveryservicesbackup.models.DayOfWeek]
    :param weeks_of_the_month: List of weeks of month.
    :type weeks_of_the_month: list[str or
     ~azure.mgmt.recoveryservicesbackup.models.WeekOfMonth]
    """

    _attribute_map = {
        'days_of_the_week': {'key': 'daysOfTheWeek', 'type': '[DayOfWeek]'},
        'weeks_of_the_month': {'key': 'weeksOfTheMonth', 'type': '[WeekOfMonth]'},
    }

    def __init__(self, days_of_the_week=None, weeks_of_the_month=None):
        super(WeeklyRetentionFormat, self).__init__()
        self.days_of_the_week = days_of_the_week
        self.weeks_of_the_month = weeks_of_the_month
