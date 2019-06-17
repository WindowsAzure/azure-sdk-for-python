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


class BillingMeters(Model):
    """The billing meters.

    :param meter_parameter: The virtual machine sizes.
    :type meter_parameter: str
    :param meter: The HDInsight meter guid.
    :type meter: str
    :param unit: The unit of meter, VMHours or CoreHours.
    :type unit: str
    """

    _attribute_map = {
        'meter_parameter': {'key': 'meterParameter', 'type': 'str'},
        'meter': {'key': 'meter', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
    }

    def __init__(self, *, meter_parameter: str=None, meter: str=None, unit: str=None, **kwargs) -> None:
        super(BillingMeters, self).__init__(**kwargs)
        self.meter_parameter = meter_parameter
        self.meter = meter
        self.unit = unit
