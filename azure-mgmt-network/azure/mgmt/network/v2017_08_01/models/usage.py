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
    """Describes network resource usage.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource identifier.
    :vartype id: str
    :ivar unit: An enum describing the unit of measurement. Default value:
     "Count" .
    :vartype unit: str
    :param current_value: The current value of the usage.
    :type current_value: long
    :param limit: The limit of usage.
    :type limit: long
    :param name: The name of the type of usage.
    :type name: ~azure.mgmt.network.v2017_08_01.models.UsageName
    """

    _validation = {
        'id': {'readonly': True},
        'unit': {'required': True, 'constant': True},
        'current_value': {'required': True},
        'limit': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
        'current_value': {'key': 'currentValue', 'type': 'long'},
        'limit': {'key': 'limit', 'type': 'long'},
        'name': {'key': 'name', 'type': 'UsageName'},
    }

    unit = "Count"

    def __init__(self, current_value, limit, name):
        super(Usage, self).__init__()
        self.id = None
        self.current_value = current_value
        self.limit = limit
        self.name = name
