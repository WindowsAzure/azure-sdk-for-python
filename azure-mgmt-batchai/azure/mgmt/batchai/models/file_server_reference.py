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


class FileServerReference(Model):
    """Provides required information, for the service to be able to mount Azure
    FileShare on the cluster nodes.

    :param file_server: Reference to the file server resource.
    :type file_server: ~azure.mgmt.batchai.models.ResourceId
    :param source_directory: Specifies the source directory in File Server
     that needs to be mounted. If this property is not specified, the entire
     File Server will be mounted.
    :type source_directory: str
    :param relative_mount_path: Specifies the relative path on the compute
     node where the File Server will be mounted. Note that all file shares will
     be mounted under $AZ_BATCHAI_MOUNT_ROOT location.
    :type relative_mount_path: str
    :param mount_options: Specifies the mount options for File Server.
    :type mount_options: str
    """

    _validation = {
        'file_server': {'required': True},
        'relative_mount_path': {'required': True},
    }

    _attribute_map = {
        'file_server': {'key': 'fileServer', 'type': 'ResourceId'},
        'source_directory': {'key': 'sourceDirectory', 'type': 'str'},
        'relative_mount_path': {'key': 'relativeMountPath', 'type': 'str'},
        'mount_options': {'key': 'mountOptions', 'type': 'str'},
    }

    def __init__(self, file_server, relative_mount_path, source_directory=None, mount_options=None):
        super(FileServerReference, self).__init__()
        self.file_server = file_server
        self.source_directory = source_directory
        self.relative_mount_path = relative_mount_path
        self.mount_options = mount_options
