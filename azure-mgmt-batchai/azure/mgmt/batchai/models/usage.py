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
    """Describes Batch AI Resource Usage.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar unit: Required. An enum describing the unit of usage measurement.
     Default value: "Count" .
    :vartype unit: str
    :param current_value: Required. The current usage of the resource.
    :type current_value: int
    :param limit: Required. The maximum permitted usage of the resource.
    :type limit: long
    :param name: Required. The name of the type of usage.
    :type name: ~azure.mgmt.batchai.models.UsageName
    """

    _validation = {
        'unit': {'required': True, 'constant': True},
        'current_value': {'required': True},
        'limit': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'unit': {'key': 'unit', 'type': 'str'},
        'current_value': {'key': 'currentValue', 'type': 'int'},
        'limit': {'key': 'limit', 'type': 'long'},
        'name': {'key': 'name', 'type': 'UsageName'},
    }

    unit = "Count"

    def __init__(self, **kwargs):
        super(Usage, self).__init__(**kwargs)
        self.current_value = kwargs.get('current_value', None)
        self.limit = kwargs.get('limit', None)
        self.name = kwargs.get('name', None)
