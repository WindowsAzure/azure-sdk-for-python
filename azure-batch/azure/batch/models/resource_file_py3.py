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


class ResourceFile(Model):
    """A single file or multiple files to be downloaded to a compute node.

    :param auto_storage_container_name: The storage container name in the auto
     storage account. The autoStorageContainerName, storageContainerUrl and
     httpUrl properties are mutually exclusive and one of them must be
     specified.
    :type auto_storage_container_name: str
    :param storage_container_url: The URL of the blob container within Azure
     Blob Storage. The autoStorageContainerName, storageContainerUrl and
     httpUrl properties are mutually exclusive and one of them must be
     specified. This URL must be readable and listable using anonymous access;
     that is, the Batch service does not present any credentials when
     downloading blobs from the container. There are two ways to get such a URL
     for a container in Azure storage: include a Shared Access Signature (SAS)
     granting read permissions on the container, or set the ACL for the
     container to allow public access.
    :type storage_container_url: str
    :param http_url: The URL of the file to download. The
     autoStorageContainerName, storageContainerUrl and httpUrl properties are
     mutually exclusive and one of them must be specified. If the URL points to
     Azure Blob Storage, it must be readable using anonymous access; that is,
     the Batch service does not present any credentials when downloading the
     blob. There are two ways to get such a URL for a blob in Azure storage:
     include a Shared Access Signature (SAS) granting read permissions on the
     blob, or set the ACL for the blob or its container to allow public access.
    :type http_url: str
    :param blob_prefix: The blob prefix to use when downloading blobs from an
     Azure Storage container. Only the blobs whose names begin with the
     specified prefix will be downloaded. The property is valid only when
     autoStorageContainerName or storageContainerUrl is used. This prefix can
     be a partial filename or a subdirectory. If a prefix is not specified, all
     the files in the container will be downloaded.
    :type blob_prefix: str
    :param file_path: The location on the compute node to which to download
     the file(s), relative to the task's working directory. If the httpUrl
     property is specified, the filePath is required and describes the path
     which the file will be downloaded to, including the filename. Otherwise,
     if the autoStorageContainerName or storageContainerUrl property is
     specified, filePath is optional and is the directory to download the files
     to. In the case where filePath is used as a directory, any directory
     structure already associated with the input data will be retained in full
     and appended to the specified filePath directory. The specified relative
     path cannot break out of the task's working directory (for example by
     using '..').
    :type file_path: str
    :param file_mode: The file permission mode attribute in octal format. This
     property applies only to files being downloaded to Linux compute nodes. It
     will be ignored if it is specified for a resourceFile which will be
     downloaded to a Windows node. If this property is not specified for a
     Linux node, then a default value of 0770 is applied to the file.
    :type file_mode: str
    """

    _attribute_map = {
        'auto_storage_container_name': {'key': 'autoStorageContainerName', 'type': 'str'},
        'storage_container_url': {'key': 'storageContainerUrl', 'type': 'str'},
        'http_url': {'key': 'httpUrl', 'type': 'str'},
        'blob_prefix': {'key': 'blobPrefix', 'type': 'str'},
        'file_path': {'key': 'filePath', 'type': 'str'},
        'file_mode': {'key': 'fileMode', 'type': 'str'},
    }

    def __init__(self, *, auto_storage_container_name: str=None, storage_container_url: str=None, http_url: str=None, blob_prefix: str=None, file_path: str=None, file_mode: str=None, **kwargs) -> None:
        super(ResourceFile, self).__init__(**kwargs)
        self.auto_storage_container_name = auto_storage_container_name
        self.storage_container_url = storage_container_url
        self.http_url = http_url
        self.blob_prefix = blob_prefix
        self.file_path = file_path
        self.file_mode = file_mode
