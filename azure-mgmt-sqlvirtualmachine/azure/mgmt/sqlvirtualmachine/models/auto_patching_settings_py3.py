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


class AutoPatchingSettings(Model):
    """Set a patching window during which Windows and SQL patches will be applied.

    :param enable: Enable or disable autopatching on SQL virtual machine.
    :type enable: bool
    :param day_of_week: Day of week to apply the patch on. Possible values
     include: 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday',
     'Saturday', 'Sunday'
    :type day_of_week: str or ~azure.mgmt.sqlvirtualmachine.models.DayOfWeek
    :param maintenance_window_starting_hour: Hour of the day when patching is
     initiated. Local VM time.
    :type maintenance_window_starting_hour: int
    :param maintenance_window_duration: Duration of patching.
    :type maintenance_window_duration: int
    """

    _attribute_map = {
        'enable': {'key': 'enable', 'type': 'bool'},
        'day_of_week': {'key': 'dayOfWeek', 'type': 'DayOfWeek'},
        'maintenance_window_starting_hour': {'key': 'maintenanceWindowStartingHour', 'type': 'int'},
        'maintenance_window_duration': {'key': 'maintenanceWindowDuration', 'type': 'int'},
    }

    def __init__(self, *, enable: bool=None, day_of_week=None, maintenance_window_starting_hour: int=None, maintenance_window_duration: int=None, **kwargs) -> None:
        super(AutoPatchingSettings, self).__init__(**kwargs)
        self.enable = enable
        self.day_of_week = day_of_week
        self.maintenance_window_starting_hour = maintenance_window_starting_hour
        self.maintenance_window_duration = maintenance_window_duration
