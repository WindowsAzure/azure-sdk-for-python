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

from .sub_resource import SubResource


class ManagedDiskParameters(SubResource):
    """The parameters of a managed disk.

    :param id: Resource Id
    :type id: str
    :param storage_account_type: Specifies the storage account type for the
     managed disk. Possible values are: Standard_LRS or Premium_LRS. Possible
     values include: 'Standard_LRS', 'Premium_LRS'
    :type storage_account_type: str or
     ~azure.mgmt.compute.v2016_04_30_preview.models.StorageAccountTypes
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'storage_account_type': {'key': 'storageAccountType', 'type': 'StorageAccountTypes'},
    }

    def __init__(self, id=None, storage_account_type=None):
        super(ManagedDiskParameters, self).__init__(id=id)
        self.storage_account_type = storage_account_type
