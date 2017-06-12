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

from .schedule_policy import SchedulePolicy


class LongTermSchedulePolicy(SchedulePolicy):
    """Long term policy schedule.

    :param schedule_policy_type: Polymorphic Discriminator
    :type schedule_policy_type: str
    """

    _validation = {
        'schedule_policy_type': {'required': True},
    }

    def __init__(self):
        super(LongTermSchedulePolicy, self).__init__()
        self.schedule_policy_type = 'LongTermSchedulePolicy'
