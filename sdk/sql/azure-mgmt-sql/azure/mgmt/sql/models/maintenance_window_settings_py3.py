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


class MaintenanceWindowSettings(Model):
    """The properties of managed instance maintenance window.

    All required parameters must be populated in order to send to Azure.

    :param time_of_upgrade: Specifies time of upgrade for maintenance window
     of managed instance.
    :type time_of_upgrade: str
    :param dates: Specifies days of the month when maintenance window is to be
     opened.
    :type dates: list[int]
    :param scheduled_days: Specifies days in a week when maintenance window is
     to be opened.
    :type scheduled_days: list[str]
    :param scheduled_weeks: Specifies weeks on which the maintenance window
     should be opened. E.g. if '1,3' is provided and for ScheduledDays Sunday
     is provided,
     that means that window is to be opened on Sunday every first and third
     week.
    :type scheduled_weeks: list[int]
    :param one_off_start_time: Specifies one off start time for a maintenance
     window. This is the time when window will be opened for the first time.
    :type one_off_start_time: datetime
    :param frequency: Required. Specifies frequency of a maintenance window.
     None - No recurring pattern,
     Daily - Daily window; specified by days of week,
     Monthly - Monthly window; specified by dates in a month,
     Flexible - Flexible window; specified by week numbers and days of week.
     Possible values include: 'NonRecurrent', 'Weekly', 'Monthly', 'Flexible'
    :type frequency: str or ~azure.mgmt.sql.models.MaintenanceWindowFrequency
    :param customer_time_zone: Required. Specifies the timezone for which the
     window will be set. See reference for TimezoneId of ManagedInstance.
    :type customer_time_zone: str
    """

    _validation = {
        'frequency': {'required': True},
        'customer_time_zone': {'required': True},
    }

    _attribute_map = {
        'time_of_upgrade': {'key': 'timeOfUpgrade', 'type': 'str'},
        'dates': {'key': 'dates', 'type': '[int]'},
        'scheduled_days': {'key': 'scheduledDays', 'type': '[str]'},
        'scheduled_weeks': {'key': 'scheduledWeeks', 'type': '[int]'},
        'one_off_start_time': {'key': 'oneOffStartTime', 'type': 'iso-8601'},
        'frequency': {'key': 'frequency', 'type': 'str'},
        'customer_time_zone': {'key': 'customerTimeZone', 'type': 'str'},
    }

    def __init__(self, *, frequency, customer_time_zone: str, time_of_upgrade: str=None, dates=None, scheduled_days=None, scheduled_weeks=None, one_off_start_time=None, **kwargs) -> None:
        super(MaintenanceWindowSettings, self).__init__(**kwargs)
        self.time_of_upgrade = time_of_upgrade
        self.dates = dates
        self.scheduled_days = scheduled_days
        self.scheduled_weeks = scheduled_weeks
        self.one_off_start_time = one_off_start_time
        self.frequency = frequency
        self.customer_time_zone = customer_time_zone
