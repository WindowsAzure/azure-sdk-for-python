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


class Recurrence(Model):
    """The repeating times at which this profile begins. This element is not used
    if the FixedDate element is used.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar frequency: Required. the recurrence frequency. How often the
     schedule profile should take effect. This value must be Week, meaning each
     week will have the same set of profiles. For example, to set a daily
     schedule, set **schedule** to every day of the week. The frequency
     property specifies that the schedule is repeated weekly. Default value:
     "Week" .
    :vartype frequency: str
    :param schedule: Required. the scheduling constraints for when the profile
     begins.
    :type schedule: ~azure.mgmt.monitor.models.RecurrentSchedule
    """

    _validation = {
        'frequency': {'required': True, 'constant': True},
        'schedule': {'required': True},
    }

    _attribute_map = {
        'frequency': {'key': 'frequency', 'type': 'str'},
        'schedule': {'key': 'schedule', 'type': 'RecurrentSchedule'},
    }

    frequency = "Week"

    def __init__(self, **kwargs):
        super(Recurrence, self).__init__(**kwargs)
        self.schedule = kwargs.get('schedule', None)
