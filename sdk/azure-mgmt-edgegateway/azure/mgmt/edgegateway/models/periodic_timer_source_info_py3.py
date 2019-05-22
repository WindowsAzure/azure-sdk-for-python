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


class PeriodicTimerSourceInfo(Model):
    """Periodic timer event source.

    All required parameters must be populated in order to send to Azure.

    :param start_time: Required. The time of the day that results in a valid
     trigger. Schedule is computed with reference to the time specified up to
     seconds. If timezone is not specified the time will considered to be in
     device timezone. The value will always be returned as UTC time.
    :type start_time: datetime
    :param schedule: Required. Periodic frequency at which timer event needs
     to be raised. Supports daily, hourly, minutes, and seconds.
    :type schedule: str
    :param topic: Topic where periodic events are published to IoT device.
    :type topic: str
    """

    _validation = {
        'start_time': {'required': True},
        'schedule': {'required': True},
    }

    _attribute_map = {
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'schedule': {'key': 'schedule', 'type': 'str'},
        'topic': {'key': 'topic', 'type': 'str'},
    }

    def __init__(self, *, start_time, schedule: str, topic: str=None, **kwargs) -> None:
        super(PeriodicTimerSourceInfo, self).__init__(**kwargs)
        self.start_time = start_time
        self.schedule = schedule
        self.topic = topic
