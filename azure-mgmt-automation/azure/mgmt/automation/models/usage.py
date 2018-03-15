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


class Usage(Model):
    """Definition of Usage.

    :param id: Gets or sets the id of the resource.
    :type id: str
    :param name: Gets or sets the usage counter name.
    :type name: ~azure.mgmt.automation.models.UsageCounterName
    :param unit: Gets or sets the usage unit name.
    :type unit: str
    :param current_value: Gets or sets the current usage value.
    :type current_value: float
    :param limit: Gets or sets max limit. -1 for unlimited
    :type limit: long
    :param throttle_status: Gets or sets the throttle status.
    :type throttle_status: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'UsageCounterName'},
        'unit': {'key': 'unit', 'type': 'str'},
        'current_value': {'key': 'currentValue', 'type': 'float'},
        'limit': {'key': 'limit', 'type': 'long'},
        'throttle_status': {'key': 'throttleStatus', 'type': 'str'},
    }

    def __init__(self, id=None, name=None, unit=None, current_value=None, limit=None, throttle_status=None):
        super(Usage, self).__init__()
        self.id = id
        self.name = name
        self.unit = unit
        self.current_value = current_value
        self.limit = limit
        self.throttle_status = throttle_status
