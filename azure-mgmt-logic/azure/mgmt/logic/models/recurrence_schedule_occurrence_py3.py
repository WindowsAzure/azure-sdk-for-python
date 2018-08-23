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


class RecurrenceScheduleOccurrence(Model):
    """The recurrence schedule occurrence.

    :param day: The day of the week. Possible values include: 'Sunday',
     'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'
    :type day: str or ~azure.mgmt.logic.models.DayOfWeek
    :param occurrence: The occurrence.
    :type occurrence: int
    """

    _attribute_map = {
        'day': {'key': 'day', 'type': 'str'},
        'occurrence': {'key': 'occurrence', 'type': 'int'},
    }

    def __init__(self, *, day=None, occurrence: int=None, **kwargs) -> None:
        super(RecurrenceScheduleOccurrence, self).__init__(**kwargs)
        self.day = day
        self.occurrence = occurrence
