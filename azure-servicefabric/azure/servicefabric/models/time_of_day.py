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


class TimeOfDay(Model):
    """Defines an hour and minute of the day specified in 24 hour time.

    :param hour: Represents the hour of the day. Value must be between 0 and
     23 inclusive.
    :type hour: int
    :param minute: Represents the minute of the hour. Value must be between 0
     to 59 inclusive.
    :type minute: int
    """

    _validation = {
        'hour': {'maximum': 23, 'minimum': 0},
        'minute': {'maximum': 59, 'minimum': 0},
    }

    _attribute_map = {
        'hour': {'key': 'Hour', 'type': 'int'},
        'minute': {'key': 'Minute', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(TimeOfDay, self).__init__(**kwargs)
        self.hour = kwargs.get('hour', None)
        self.minute = kwargs.get('minute', None)
