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


class ValueDelta(Model):
    """The value of the delta.

    :param operation_type: The operation type. Possible values include:
     'Undefined', 'Add', 'Update', 'Delete'
    :type operation_type: str or
     ~azure.mgmt.adhybridhealthservice.models.ValueDeltaOperationType
    :param value: The value of the delta.
    :type value: str
    """

    _attribute_map = {
        'operation_type': {'key': 'operationType', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, *, operation_type=None, value: str=None, **kwargs) -> None:
        super(ValueDelta, self).__init__(**kwargs)
        self.operation_type = operation_type
        self.value = value
