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


class ScheduleEntry(Model):
    """Patch schedule entry for a Premium Redis Cache.

    :param day_of_week: Day of the week when a cache can be patched. Possible
     values include: 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday',
     'Saturday', 'Sunday', 'Everyday', 'Weekend'
    :type day_of_week: str or ~azure.mgmt.redis.models.DayOfWeek
    :param start_hour_utc: Start hour after which cache patching can start.
    :type start_hour_utc: int
    :param maintenance_window: ISO8601 timespan specifying how much time cache
     patching can take.
    :type maintenance_window: timedelta
    """

    _validation = {
        'day_of_week': {'required': True},
        'start_hour_utc': {'required': True},
    }

    _attribute_map = {
        'day_of_week': {'key': 'dayOfWeek', 'type': 'DayOfWeek'},
        'start_hour_utc': {'key': 'startHourUtc', 'type': 'int'},
        'maintenance_window': {'key': 'maintenanceWindow', 'type': 'duration'},
    }

    def __init__(self, day_of_week, start_hour_utc, maintenance_window=None):
        super(ScheduleEntry, self).__init__()
        self.day_of_week = day_of_week
        self.start_hour_utc = start_hour_utc
        self.maintenance_window = maintenance_window
