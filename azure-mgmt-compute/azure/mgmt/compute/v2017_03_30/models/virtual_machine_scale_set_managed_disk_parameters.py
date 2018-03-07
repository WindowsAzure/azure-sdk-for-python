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


class VirtualMachineScaleSetManagedDiskParameters(Model):
    """Describes the parameters of a ScaleSet managed disk.

    :param storage_account_type: Specifies the storage account type for the
     managed disk. Possible values are: Standard_LRS or Premium_LRS. Possible
     values include: 'Standard_LRS', 'Premium_LRS'
    :type storage_account_type: str or
     ~azure.mgmt.compute.v2017_03_30.models.StorageAccountTypes
    """

    _attribute_map = {
        'storage_account_type': {'key': 'storageAccountType', 'type': 'StorageAccountTypes'},
    }

    def __init__(self, **kwargs):
        super(VirtualMachineScaleSetManagedDiskParameters, self).__init__(**kwargs)
        self.storage_account_type = kwargs.get('storage_account_type', None)
