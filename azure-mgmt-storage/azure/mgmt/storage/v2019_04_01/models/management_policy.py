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

from .resource import Resource


class ManagementPolicy(Resource):
    """The Get Storage Account ManagementPolicies operation response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :ivar last_modified_time: Returns the date and time the ManagementPolicies
     was last modified.
    :vartype last_modified_time: datetime
    :param policy: Required. The Storage Account ManagementPolicy, in JSON
     format. See more details in:
     https://docs.microsoft.com/en-us/azure/storage/common/storage-lifecycle-managment-concepts.
    :type policy:
     ~azure.mgmt.storage.v2019_04_01.models.ManagementPolicySchema
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'last_modified_time': {'readonly': True},
        'policy': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'last_modified_time': {'key': 'properties.lastModifiedTime', 'type': 'iso-8601'},
        'policy': {'key': 'properties.policy', 'type': 'ManagementPolicySchema'},
    }

    def __init__(self, **kwargs):
        super(ManagementPolicy, self).__init__(**kwargs)
        self.last_modified_time = None
        self.policy = kwargs.get('policy', None)
