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


class ActivityLogAlertLeafCondition(Model):
    """An Activity Log alert condition that is met by comparing an activity log
    field and value.

    :param field: The name of the field that this condition will examine. The
     possible values for this field are (case-insensitive): 'resourceId',
     'category', 'caller', 'level', 'operationName', 'resourceGroup',
     'resourceProvider', 'status', 'subStatus', 'resourceType', or anything
     beginning with 'properties.'.
    :type field: str
    :param equals: The field value will be compared to this value
     (case-insensitive) to determine if the condition is met.
    :type equals: str
    """

    _validation = {
        'field': {'required': True},
        'equals': {'required': True},
    }

    _attribute_map = {
        'field': {'key': 'field', 'type': 'str'},
        'equals': {'key': 'equals', 'type': 'str'},
    }

    def __init__(self, field, equals):
        self.field = field
        self.equals = equals
