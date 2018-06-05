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


class VaultUsage(Model):
    """Usages of a vault.

    :param unit: Unit of the usage. Possible values include: 'Count', 'Bytes',
     'Seconds', 'Percent', 'CountPerSecond', 'BytesPerSecond'
    :type unit: str or ~azure.mgmt.recoveryservices.models.UsagesUnit
    :param quota_period: Quota period of usage.
    :type quota_period: str
    :param next_reset_time: Next reset time of usage.
    :type next_reset_time: datetime
    :param current_value: Current value of usage.
    :type current_value: long
    :param limit: Limit of usage.
    :type limit: long
    :param name: Name of usage.
    :type name: ~azure.mgmt.recoveryservices.models.NameInfo
    """

    _attribute_map = {
        'unit': {'key': 'unit', 'type': 'str'},
        'quota_period': {'key': 'quotaPeriod', 'type': 'str'},
        'next_reset_time': {'key': 'nextResetTime', 'type': 'iso-8601'},
        'current_value': {'key': 'currentValue', 'type': 'long'},
        'limit': {'key': 'limit', 'type': 'long'},
        'name': {'key': 'name', 'type': 'NameInfo'},
    }

    def __init__(self, *, unit=None, quota_period: str=None, next_reset_time=None, current_value: int=None, limit: int=None, name=None, **kwargs) -> None:
        super(VaultUsage, self).__init__(**kwargs)
        self.unit = unit
        self.quota_period = quota_period
        self.next_reset_time = next_reset_time
        self.current_value = current_value
        self.limit = limit
        self.name = name
