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


class ExportSchedule(Model):
    """The schedule associated with a export.

    All required parameters must be populated in order to send to Azure.

    :param status: The status of the schedule. Whether active or not. If
     inactive, the export's scheduled execution is paused. Possible values
     include: 'Active', 'Inactive'
    :type status: str or ~azure.mgmt.costmanagement.models.StatusType
    :param recurrence: Required. The schedule recurrence. Possible values
     include: 'Daily', 'Weekly', 'Monthly', 'Annually'
    :type recurrence: str or ~azure.mgmt.costmanagement.models.RecurrenceType
    :param recurrence_period: Has start and end date of the recurrence. The
     start date must be in future. If present, the end date must be greater
     than start date.
    :type recurrence_period:
     ~azure.mgmt.costmanagement.models.ExportRecurrencePeriod
    """

    _validation = {
        'recurrence': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'recurrence': {'key': 'recurrence', 'type': 'str'},
        'recurrence_period': {'key': 'recurrencePeriod', 'type': 'ExportRecurrencePeriod'},
    }

    def __init__(self, **kwargs):
        super(ExportSchedule, self).__init__(**kwargs)
        self.status = kwargs.get('status', None)
        self.recurrence = kwargs.get('recurrence', None)
        self.recurrence_period = kwargs.get('recurrence_period', None)
