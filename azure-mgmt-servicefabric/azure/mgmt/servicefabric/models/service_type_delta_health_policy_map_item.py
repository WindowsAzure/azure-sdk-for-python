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


class ServiceTypeDeltaHealthPolicyMapItem(Model):
    """Defines an item in ServiceTypeDeltaHealthPolicyMap.
    .

    :param key: The key of the service type delta health policy map item. This
     is the name of the service type.
    :type key: str
    :param value: The value of the service type delta health policy map item.
     This is the ServiceTypeDeltaHealthPolicy for this service type.
    :type value: ~azure.mgmt.servicefabric.models.ServiceTypeDeltaHealthPolicy
    """

    _validation = {
        'key': {'required': True},
        'value': {'required': True},
    }

    _attribute_map = {
        'key': {'key': 'key', 'type': 'str'},
        'value': {'key': 'value', 'type': 'ServiceTypeDeltaHealthPolicy'},
    }

    def __init__(self, key, value):
        super(ServiceTypeDeltaHealthPolicyMapItem, self).__init__()
        self.key = key
        self.value = value
