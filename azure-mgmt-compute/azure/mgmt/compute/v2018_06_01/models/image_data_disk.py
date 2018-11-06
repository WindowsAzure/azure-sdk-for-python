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


class ImageDataDisk(Model):
    """Describes a data disk.

    All required parameters must be populated in order to send to Azure.

    :param lun: Required. Specifies the logical unit number of the data disk.
     This value is used to identify data disks within the VM and therefore must
     be unique for each data disk attached to a VM.
    :type lun: int
    :param snapshot: The snapshot.
    :type snapshot: ~azure.mgmt.compute.v2018_06_01.models.SubResource
    :param managed_disk: The managedDisk.
    :type managed_disk: ~azure.mgmt.compute.v2018_06_01.models.SubResource
    :param blob_uri: The Virtual Hard Disk.
    :type blob_uri: str
    :param caching: Specifies the caching requirements. <br><br> Possible
     values are: <br><br> **None** <br><br> **ReadOnly** <br><br> **ReadWrite**
     <br><br> Default: **None for Standard storage. ReadOnly for Premium
     storage**. Possible values include: 'None', 'ReadOnly', 'ReadWrite'
    :type caching: str or ~azure.mgmt.compute.v2018_06_01.models.CachingTypes
    :param disk_size_gb: Specifies the size of empty data disks in gigabytes.
     This element can be used to overwrite the name of the disk in a virtual
     machine image. <br><br> This value cannot be larger than 1023 GB
    :type disk_size_gb: int
    :param storage_account_type: Specifies the storage account type for the
     managed disk. Possible values are: Standard_LRS, Premium_LRS, and
     StandardSSD_LRS. Possible values include: 'Standard_LRS', 'Premium_LRS',
     'StandardSSD_LRS', 'UltraSSD_LRS'
    :type storage_account_type: str or
     ~azure.mgmt.compute.v2018_06_01.models.StorageAccountTypes
    """

    _validation = {
        'lun': {'required': True},
    }

    _attribute_map = {
        'lun': {'key': 'lun', 'type': 'int'},
        'snapshot': {'key': 'snapshot', 'type': 'SubResource'},
        'managed_disk': {'key': 'managedDisk', 'type': 'SubResource'},
        'blob_uri': {'key': 'blobUri', 'type': 'str'},
        'caching': {'key': 'caching', 'type': 'CachingTypes'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'storage_account_type': {'key': 'storageAccountType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ImageDataDisk, self).__init__(**kwargs)
        self.lun = kwargs.get('lun', None)
        self.snapshot = kwargs.get('snapshot', None)
        self.managed_disk = kwargs.get('managed_disk', None)
        self.blob_uri = kwargs.get('blob_uri', None)
        self.caching = kwargs.get('caching', None)
        self.disk_size_gb = kwargs.get('disk_size_gb', None)
        self.storage_account_type = kwargs.get('storage_account_type', None)
