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
     managed disk. UltraSSD_LRS can only be used for data disks. Possible
     values include: 'Standard_LRS', 'Premium_LRS', 'StandardSSD_LRS',
     'UltraSSD_LRS'
    :type storage_account_type: str or
     ~azure.mgmt.compute.v2018_06_01.models.StorageAccountTypes
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'storage_account_type': {'key': 'storageAccountType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ManagedDiskParameters, self).__init__(**kwargs)
        self.storage_account_type = kwargs.get('storage_account_type', None)
