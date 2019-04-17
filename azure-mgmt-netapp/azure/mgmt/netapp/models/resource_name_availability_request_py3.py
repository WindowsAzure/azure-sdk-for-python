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


class ResourceNameAvailabilityRequest(Model):
    """Resource name availability request content.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Resource name to verify.
    :type name: str
    :param type: Required. Resource type used for verification. Possible
     values include: 'Microsoft.NetApp/netAppAccount',
     'Microsoft.NetApp/netAppAccount/capacityPools',
     'Microsoft.NetApp/netAppAccount/capacityPools/volumes',
     'Microsoft.NetApp/netAppAccount/capacityPools/volumes/snapshots'
    :type type: str or ~azure.mgmt.netapp.models.CheckNameResourceTypes
    :param resource_group: Required. Is fully qualified domain name.
    :type resource_group: str
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'resource_group': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'resource_group': {'key': 'resourceGroup', 'type': 'str'},
    }

    def __init__(self, *, name: str, type, resource_group: str, **kwargs) -> None:
        super(ResourceNameAvailabilityRequest, self).__init__(**kwargs)
        self.name = name
        self.type = type
        self.resource_group = resource_group
