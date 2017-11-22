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


class RequestsBasedTrigger(Model):
    """Trigger based on total requests.

    :param count: Request Count.
    :type count: int
    :param time_interval: Time interval.
    :type time_interval: str
    """

    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'time_interval': {'key': 'timeInterval', 'type': 'str'},
    }

    def __init__(self, count=None, time_interval=None):
        self.count = count
        self.time_interval = time_interval
