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


class RegistryUsage(Model):
    """The quota usage for a container registry.

    :param name: The name of the usage.
    :type name: str
    :param limit: The limit of the usage.
    :type limit: long
    :param current_value: The current value of the usage.
    :type current_value: long
    :param unit: The unit of measurement. Possible values include: 'Count',
     'Bytes'
    :type unit: str or
     ~azure.mgmt.containerregistry.v2019_04_01.models.RegistryUsageUnit
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'limit': {'key': 'limit', 'type': 'long'},
        'current_value': {'key': 'currentValue', 'type': 'long'},
        'unit': {'key': 'unit', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistryUsage, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.limit = kwargs.get('limit', None)
        self.current_value = kwargs.get('current_value', None)
        self.unit = kwargs.get('unit', None)
