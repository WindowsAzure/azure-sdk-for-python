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


class HttpLogsConfig(Model):
    """Http logs configuration.

    :param file_system: Http logs to file system configuration.
    :type file_system: ~azure.mgmt.web.models.FileSystemHttpLogsConfig
    :param azure_blob_storage: Http logs to azure blob storage configuration.
    :type azure_blob_storage:
     ~azure.mgmt.web.models.AzureBlobStorageHttpLogsConfig
    """

    _attribute_map = {
        'file_system': {'key': 'fileSystem', 'type': 'FileSystemHttpLogsConfig'},
        'azure_blob_storage': {'key': 'azureBlobStorage', 'type': 'AzureBlobStorageHttpLogsConfig'},
    }

    def __init__(self, file_system=None, azure_blob_storage=None):
        super(HttpLogsConfig, self).__init__()
        self.file_system = file_system
        self.azure_blob_storage = azure_blob_storage
