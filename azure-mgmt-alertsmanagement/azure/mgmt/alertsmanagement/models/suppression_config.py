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


class SuppressionConfig(Model):
    """Suppression logic for a given action rule.

    All required parameters must be populated in order to send to Azure.

    :param recurrence_type: Required. Specifies when the suppression should be
     applied. Possible values include: 'Always', 'Once', 'Daily', 'Weekly',
     'Monthly'
    :type recurrence_type: str or
     ~azure.mgmt.alertsmanagement.models.SuppressionType
    :param schedule: suppression schedule configuration
    :type schedule: ~azure.mgmt.alertsmanagement.models.SuppressionSchedule
    """

    _validation = {
        'recurrence_type': {'required': True},
    }

    _attribute_map = {
        'recurrence_type': {'key': 'recurrenceType', 'type': 'str'},
        'schedule': {'key': 'schedule', 'type': 'SuppressionSchedule'},
    }

    def __init__(self, **kwargs):
        super(SuppressionConfig, self).__init__(**kwargs)
        self.recurrence_type = kwargs.get('recurrence_type', None)
        self.schedule = kwargs.get('schedule', None)
