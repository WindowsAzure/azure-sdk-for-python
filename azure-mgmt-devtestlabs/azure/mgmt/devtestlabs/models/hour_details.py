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


class HourDetails(Model):
    """Properties of an hourly schedule.

    :param minute: Minutes of the hour the schedule will run.
    :type minute: int
    """

    _attribute_map = {
        'minute': {'key': 'minute', 'type': 'int'},
    }

    def __init__(self, minute=None):
        super(HourDetails, self).__init__()
        self.minute = minute
