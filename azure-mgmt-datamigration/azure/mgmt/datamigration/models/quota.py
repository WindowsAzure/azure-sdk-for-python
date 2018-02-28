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


class Quota(Model):
    """Describes a quota for or usage details about a resource.

    :param current_value: The current value of the quota. If null or missing,
     the current value cannot be determined in the context of the request.
    :type current_value: float
    :param id: The resource ID of the quota object
    :type id: str
    :param limit: The maximum value of the quota. If null or missing, the
     quota has no maximum, in which case it merely tracks usage.
    :type limit: float
    :param name: The name of the quota
    :type name: ~azure.mgmt.datamigration.models.QuotaName
    :param unit: The unit for the quota, such as Count, Bytes, BytesPerSecond,
     etc.
    :type unit: str
    """

    _attribute_map = {
        'current_value': {'key': 'currentValue', 'type': 'float'},
        'id': {'key': 'id', 'type': 'str'},
        'limit': {'key': 'limit', 'type': 'float'},
        'name': {'key': 'name', 'type': 'QuotaName'},
        'unit': {'key': 'unit', 'type': 'str'},
    }

    def __init__(self, current_value=None, id=None, limit=None, name=None, unit=None):
        super(Quota, self).__init__()
        self.current_value = current_value
        self.id = id
        self.limit = limit
        self.name = name
        self.unit = unit
