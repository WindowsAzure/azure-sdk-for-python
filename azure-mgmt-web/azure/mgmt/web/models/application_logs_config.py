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


class ApplicationLogsConfig(Model):
    """Application logs configuration.

    :param file_system: Application logs to file system configuration.
    :type file_system: ~azure.mgmt.web.models.FileSystemApplicationLogsConfig
    :param azure_table_storage: Application logs to azure table storage
     configuration.
    :type azure_table_storage:
     ~azure.mgmt.web.models.AzureTableStorageApplicationLogsConfig
    :param azure_blob_storage: Application logs to blob storage configuration.
    :type azure_blob_storage:
     ~azure.mgmt.web.models.AzureBlobStorageApplicationLogsConfig
    """

    _attribute_map = {
        'file_system': {'key': 'fileSystem', 'type': 'FileSystemApplicationLogsConfig'},
        'azure_table_storage': {'key': 'azureTableStorage', 'type': 'AzureTableStorageApplicationLogsConfig'},
        'azure_blob_storage': {'key': 'azureBlobStorage', 'type': 'AzureBlobStorageApplicationLogsConfig'},
    }

    def __init__(self, file_system=None, azure_table_storage=None, azure_blob_storage=None):
        super(ApplicationLogsConfig, self).__init__()
        self.file_system = file_system
        self.azure_table_storage = azure_table_storage
        self.azure_blob_storage = azure_blob_storage
