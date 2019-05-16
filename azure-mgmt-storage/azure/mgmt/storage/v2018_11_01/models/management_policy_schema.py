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


class ManagementPolicySchema(Model):
    """The Storage Account ManagementPolicies Rules. See more details in:
    https://docs.microsoft.com/en-us/azure/storage/common/storage-lifecycle-managment-concepts.

    All required parameters must be populated in order to send to Azure.

    :param rules: Required. The Storage Account ManagementPolicies Rules. See
     more details in:
     https://docs.microsoft.com/en-us/azure/storage/common/storage-lifecycle-managment-concepts.
    :type rules:
     list[~azure.mgmt.storage.v2018_11_01.models.ManagementPolicyRule]
    """

    _validation = {
        'rules': {'required': True},
    }

    _attribute_map = {
        'rules': {'key': 'rules', 'type': '[ManagementPolicyRule]'},
    }

    def __init__(self, **kwargs):
        super(ManagementPolicySchema, self).__init__(**kwargs)
        self.rules = kwargs.get('rules', None)
