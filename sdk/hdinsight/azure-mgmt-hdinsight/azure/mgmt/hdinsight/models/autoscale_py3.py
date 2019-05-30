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


class Autoscale(Model):
    """The autoscale request parameters.

    :param capacity: Parameters for load-based autoscale
    :type capacity: ~azure.mgmt.hdinsight.models.AutoscaleCapacity
    :param recurrence: Parameters for schedule-based autoscale
    :type recurrence: ~azure.mgmt.hdinsight.models.AutoscaleRecurrence
    """

    _attribute_map = {
        'capacity': {'key': 'capacity', 'type': 'AutoscaleCapacity'},
        'recurrence': {'key': 'recurrence', 'type': 'AutoscaleRecurrence'},
    }

    def __init__(self, *, capacity=None, recurrence=None, **kwargs) -> None:
        super(Autoscale, self).__init__(**kwargs)
        self.capacity = capacity
        self.recurrence = recurrence
