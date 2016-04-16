# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class HttpLogsConfig(Model):
    """
    Http logs configuration

    :param file_system: Http logs to file system configuration
    :type file_system: :class:`FileSystemHttpLogsConfig
     <websitemanagementclient.models.FileSystemHttpLogsConfig>`
    :param azure_blob_storage: Http logs to azure blob storage configuration
    :type azure_blob_storage: :class:`AzureBlobStorageHttpLogsConfig
     <websitemanagementclient.models.AzureBlobStorageHttpLogsConfig>`
    """ 

    _attribute_map = {
        'file_system': {'key': 'fileSystem', 'type': 'FileSystemHttpLogsConfig'},
        'azure_blob_storage': {'key': 'azureBlobStorage', 'type': 'AzureBlobStorageHttpLogsConfig'},
    }

    def __init__(self, file_system=None, azure_blob_storage=None):
        self.file_system = file_system
        self.azure_blob_storage = azure_blob_storage
